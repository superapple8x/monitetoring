use ratatui::{
    widgets::{Block, Borders, Paragraph, Table, Row, Cell, TableState},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    Frame
};
use crate::types::{App, SortColumn, SortDirection, ChartType};
use crate::ui::{utils::format_bytes, charts::render_charts};

/// Render the bandwidth mode view with responsive chart display
pub fn render(f: &mut Frame, app: &App) {
    let terminal_height = f.size().height;
    
    // Different layouts based on chart type
    match app.chart_type {
        ChartType::SystemStacked => {
            render_system_stacked_view(f, app, terminal_height);
        },
        ChartType::ProcessLines => {
            render_process_lines_view(f, app, terminal_height);
        },
    }
}

/// Render the system stacked bandwidth view (no process table, more space for chart and top 5)
fn render_system_stacked_view(f: &mut Frame, app: &App, terminal_height: u16) {
    // Layout: Title, Chart (more space), Top 5 Processes Table, Totals
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),               // Title
                Constraint::Percentage(70),          // Chart (more space than before)
                Constraint::Min(8),                  // Top 5 processes table
                Constraint::Length(3),               // Totals
            ]
            .as_ref(),
        )
        .split(f.size());

    render_title(f, main_chunks[0], terminal_height, app);
    render_charts(f, app, main_chunks[1]);
    render_top5_processes_table(f, app, main_chunks[2]);
    render_totals_bar(f, app, main_chunks[3]);
}

/// Render the process lines view (original layout with compact process table)
fn render_process_lines_view(f: &mut Frame, app: &App, terminal_height: u16) {
    // Layout: Title, Chart (more space), Compact Top 5 Table, Totals
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),               // Title
                Constraint::Percentage(65),          // Chart (more space)
                Constraint::Length(8),               // Compact table (fixed height for top 5)
                Constraint::Length(3),               // Totals
            ]
            .as_ref(),
        )
        .split(f.size());

    render_title(f, main_chunks[0], terminal_height, app);
    render_charts(f, app, main_chunks[1]);
    render_compact_process_table(f, app, main_chunks[2]);
    render_totals_bar(f, app, main_chunks[3]);
}

/// Calculate responsive layout constraints based on terminal height
fn calculate_responsive_layout(terminal_height: u16) -> (Constraint, u16) {
    // Need at least 7 lines for table: 1 header + 5 data rows + 1 border = 7 lines minimum
    // Plus 2 lines for borders = 9 lines total for table
    let min_table_height = 9;
    
    // Fixed allocations: title (3) + totals (3) + margins (2) = 8 lines
    let fixed_allocations = 8;
    
    // Available space for chart and table
    let available_space = terminal_height.saturating_sub(fixed_allocations);
    
    if available_space < min_table_height + 8 {
        // Very small terminal: minimize chart, prioritize table
        let chart_height = available_space.saturating_sub(min_table_height).max(6);
        (Constraint::Length(chart_height), min_table_height)
    } else if available_space < 25 {
        // Small terminal: balanced but favor table visibility
        let chart_percentage = 40; // Reduced from 60%
        (Constraint::Percentage(chart_percentage), min_table_height)
    } else {
        // Normal/large terminal: use original proportions
        (Constraint::Percentage(55), min_table_height) // Slightly reduced from 60%
    }
}

/// Render the title bar for bandwidth mode with adaptive messaging
fn render_title(f: &mut Frame, area: ratatui::layout::Rect, terminal_height: u16, app: &App) {
    let navigation_text = if terminal_height < 20 {
        // Compact navigation for very small terminals
        if app.chart_type == ChartType::SystemStacked {
            "q:quit | Tab:mode | t:chart | m:traffic"
        } else {
            "q:quit | Tab:mode | t:chart | ↑/↓:select"
        }
    } else {
        // Full navigation text
        if app.chart_type == ChartType::SystemStacked {
            "q: quit | Tab: switch mode | t: chart type | m: traffic | Enter: actions"
        } else {
            "q: quit | Tab: switch mode | t: chart type | ↑/↓: select | Enter: actions"
        }
    };
    
    let title_text = if terminal_height < 20 {
        "Bandwidth View"
    } else {
        "Monitetoring – Bandwidth View"
    };
    
    let title = Paragraph::new(navigation_text)
        .block(Block::default().title(title_text).borders(Borders::ALL));
    f.render_widget(title, area);
}

/// Render the process table (compact and responsive)
fn render_process_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let terminal_width = area.width;
    let terminal_height = area.height;
    
    // Use compact headers for narrow terminals
    let header_titles_str = if terminal_width < 100 {
        // Compact headers for narrow terminals
        if app.containers_mode {
            vec!["PID", "Name", "Sent/s", "Recv/s", "Container"]
        } else {
            vec!["PID", "Name", "Sent/s", "Recv/s"]
        }
    } else {
        // Full headers for wide terminals
        if app.containers_mode {
            vec!["(P)ID", "Name", "Sent/s", "(S)ent Total", "Recv/s", "(R)eceived Total", "(C)ontainer"]
        } else {
            vec!["(P)ID", "Name", "Sent/s", "(S)ent Total", "Recv/s", "(R)eceived Total"]
        }
    };
    
    let mut header_titles: Vec<String> = header_titles_str.iter().map(|s| s.to_string()).collect();

    let sort_indicator = if app.sort_direction == SortDirection::Asc { " ▲" } else { " ▼" };
    match app.sort_by {
        SortColumn::Pid => header_titles[0].push_str(sort_indicator),
        SortColumn::Name => header_titles[1].push_str(sort_indicator),
        SortColumn::Sent => header_titles[2].push_str(sort_indicator),
        SortColumn::Received => {
            let recv_index = if terminal_width < 100 { 3 } else { 4 };
            header_titles[recv_index].push_str(sort_indicator);
        },
        SortColumn::Container if app.containers_mode => {
            let container_index = if terminal_width < 100 { 4 } else { 6 };
            header_titles[container_index].push_str(sort_indicator);
        },
        _ => {}
    }

    let header_cells: Vec<_> = header_titles
        .iter()
        .map(|h| Cell::from(h.as_str()).style(Style::default().fg(Color::Red)))
        .collect();
    let header = Row::new(header_cells);

    let sorted_stats = app.sorted_stats();
    
    // Limit the number of displayed rows for small terminals to ensure visibility
    let max_rows = if terminal_height <= 12 {
        5  // Show only top 5 for very small terminals
    } else if terminal_height <= 20 {
        10 // Show top 10 for small terminals
    } else {
        sorted_stats.len() // Show all for normal terminals
    };
    
    let rows = sorted_stats.iter().take(max_rows).map(|(pid, data)| {
        let mut style = Style::default();
        if data.has_alert {
            style = style.bg(Color::Yellow).fg(Color::Black);
        }
        if app.selected_process == Some(**pid) {
            style = style.add_modifier(Modifier::BOLD);
        }

        let cells = if terminal_width < 100 {
            // Compact layout for narrow terminals
            if app.containers_mode {
                vec![
                    Cell::from(pid.to_string()),
                    Cell::from(truncate_string(&data.name, 15)),
                    Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                    Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                    Cell::from(truncate_string(data.container_name.as_ref().unwrap_or(&"host".to_string()), 10)),
                ]
            } else {
                vec![
                    Cell::from(pid.to_string()),
                    Cell::from(truncate_string(&data.name, 20)),
                    Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                    Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                ]
            }
        } else {
            // Full layout for wide terminals
            if app.containers_mode {
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
            }
        };
        Row::new(cells).style(style)
    });

    let widths = if terminal_width < 100 {
        // Compact layout constraints
        if app.containers_mode {
            [
                Constraint::Length(6),   // PID
                Constraint::Min(15),     // Name
                Constraint::Length(10),  // Sent/s
                Constraint::Length(10),  // Recv/s
                Constraint::Min(10),     // Container
            ]
            .as_slice()
        } else {
            [
                Constraint::Length(6),   // PID
                Constraint::Min(20),     // Name
                Constraint::Length(12),  // Sent/s
                Constraint::Length(12),  // Recv/s
            ]
            .as_slice()
        }
    } else {
        // Full layout constraints
        if app.containers_mode {
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
        }
    };

    let table_title = format!("Processes ({}/{})", 
        std::cmp::min(max_rows, sorted_stats.len()), 
        sorted_stats.len()
    );

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(table_title));

    // Create table state and set selection to the currently selected process
    let mut table_state = TableState::default();
    if let Some(selected_pid) = app.selected_process {
        if let Some(index) = sorted_stats.iter().position(|(pid, _)| **pid == selected_pid) {
            if index < max_rows {
                table_state.select(Some(index));
            }
        }
    }
    
    f.render_stateful_widget(table, area, &mut table_state);
}

/// Render the top 5 processes table for SystemStacked view
fn render_top5_processes_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    if app.chart_datasets.is_empty() {
        let empty_text = Paragraph::new("No process data available")
            .block(Block::default().borders(Borders::ALL).title("Top 5 Processes"));
        f.render_widget(empty_text, area);
        return;
    }

    let terminal_width = area.width;
    
    // Header based on terminal width - no bullet points in headers
    let header_titles = if terminal_width < 80 {
        vec!["Color", "Process", "Sent/s", "Recv/s"]
    } else {
        vec!["Color", "Process Name", "Sent/s", "Received/s", "Total/s"]
    };

    let header_cells: Vec<_> = header_titles
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)))
        .collect();
    let header = Row::new(header_cells);

    // Get top 5 processes from chart datasets and their current stats
    let rows: Vec<Row> = app.chart_datasets.iter().take(5).map(|(name, _, color)| {
        // Find the process stats by name
        let (sent_rate, received_rate) = app.stats.iter()
            .find(|(_, info)| info.name == *name)
            .map(|(_, info)| (info.sent_rate, info.received_rate))
            .unwrap_or((0, 0));

        let total_rate = sent_rate + received_rate;
        
        let display_name = if terminal_width < 60 {
            truncate_string(name, 12)
        } else if terminal_width < 100 {
            truncate_string(name, 20)
        } else {
            name.clone()
        };

        let cells = if terminal_width < 80 {
            vec![
                Cell::from("●").style(Style::default().fg(*color).add_modifier(Modifier::BOLD)),
                Cell::from(display_name).style(Style::default().fg(*color)),
                Cell::from(format!("{}/s", format_bytes(sent_rate))),
                Cell::from(format!("{}/s", format_bytes(received_rate))),
            ]
        } else {
            vec![
                Cell::from("●").style(Style::default().fg(*color).add_modifier(Modifier::BOLD)),
                Cell::from(display_name).style(Style::default().fg(*color)),
                Cell::from(format!("{}/s", format_bytes(sent_rate))),
                Cell::from(format!("{}/s", format_bytes(received_rate))),
                Cell::from(format!("{}/s", format_bytes(total_rate))),
            ]
        };
        
        Row::new(cells)
    }).collect();

    let widths = if terminal_width < 80 {
        [
            Constraint::Length(5),   // Color dot
            Constraint::Min(12),     // Process name
            Constraint::Length(12),  // Sent/s
            Constraint::Length(12),  // Recv/s
        ]
        .as_slice()
    } else {
        [
            Constraint::Length(5),   // Color dot
            Constraint::Min(20),     // Process name
            Constraint::Length(12),  // Sent/s
            Constraint::Length(12),  // Recv/s
            Constraint::Length(12),  // Total/s
        ]
        .as_slice()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Top 5 Bandwidth Processes"));

    f.render_widget(table, area);
}

/// Render a compact process table (top 5 only) for ProcessLines view
fn render_compact_process_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let terminal_width = area.width;
    
    // Use compact headers for this limited space
    let header_titles_str = if app.containers_mode {
        vec!["PID", "Name", "Sent/s", "Recv/s", "Container"]
    } else {
        vec!["PID", "Name", "Sent/s", "Recv/s"]
    };
    
    let mut header_titles: Vec<String> = header_titles_str.iter().map(|s| s.to_string()).collect();

    let sort_indicator = if app.sort_direction == SortDirection::Asc { " ▲" } else { " ▼" };
    match app.sort_by {
        SortColumn::Pid => header_titles[0].push_str(sort_indicator),
        SortColumn::Name => header_titles[1].push_str(sort_indicator),
        SortColumn::Sent => header_titles[2].push_str(sort_indicator),
        SortColumn::Received => header_titles[3].push_str(sort_indicator),
        SortColumn::Container if app.containers_mode => header_titles[4].push_str(sort_indicator),
        _ => {}
    }

    let header_cells: Vec<_> = header_titles
        .iter()
        .map(|h| Cell::from(h.as_str()).style(Style::default().fg(Color::Red)))
        .collect();
    let header = Row::new(header_cells);

    let sorted_stats = app.sorted_stats();
    
    // Show only top 5 processes to save space
    let rows = sorted_stats.iter().take(5).map(|(pid, data)| {
        let mut style = Style::default();
        if data.has_alert {
            style = style.bg(Color::Yellow).fg(Color::Black);
        }
        if app.selected_process == Some(**pid) {
            style = style.add_modifier(Modifier::BOLD);
        }

        let display_name = if terminal_width < 60 {
            truncate_string(&data.name, 10)
        } else {
            truncate_string(&data.name, 15)
        };

        let cells = if app.containers_mode {
            vec![
                Cell::from(pid.to_string()),
                Cell::from(display_name),
                Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                Cell::from(truncate_string(data.container_name.as_ref().unwrap_or(&"host".to_string()), 8)),
            ]
        } else {
            vec![
                Cell::from(pid.to_string()),
                Cell::from(display_name),
                Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                Cell::from(format!("{}/s", format_bytes(data.received_rate))),
            ]
        };
        Row::new(cells).style(style)
    });

    let widths = if app.containers_mode {
        [
            Constraint::Length(6),   // PID
            Constraint::Min(10),     // Name
            Constraint::Length(10),  // Sent/s
            Constraint::Length(10),  // Recv/s
            Constraint::Length(8),   // Container
        ]
        .as_slice()
    } else {
        [
            Constraint::Length(6),   // PID
            Constraint::Min(15),     // Name
            Constraint::Length(12),  // Sent/s
            Constraint::Length(12),  // Recv/s
        ]
        .as_slice()
    };

    let table_title = format!("Top 5 Processes ({} total)", sorted_stats.len());

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(table_title));

    // Create table state and set selection to the currently selected process
    let mut table_state = TableState::default();
    if let Some(selected_pid) = app.selected_process {
        if let Some(index) = sorted_stats.iter().position(|(pid, _)| **pid == selected_pid) {
            if index < 5 {
                table_state.select(Some(index));
            }
        }
    }
    
    f.render_stateful_widget(table, area, &mut table_state);
}

/// Helper function to truncate strings to fit narrow terminals
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}

/// Render the totals bar (responsive)
fn render_totals_bar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (total_sent, total_received, total_sent_rate, total_received_rate) = app.totals();
    
    let totals_text = if area.width < 80 {
        // Compact format for narrow terminals
        format!(
            "📊 ↑{}/s ({}) ↓{}/s ({})",
            format_bytes(total_sent_rate),
            format_bytes(total_sent),
            format_bytes(total_received_rate),
            format_bytes(total_received)
        )
    } else {
        // Full format for wide terminals
        format!(
            "📊 TOTALS: Sent {}/s ({} total) | Received {}/s ({} total)",
            format_bytes(total_sent_rate),
            format_bytes(total_sent),
            format_bytes(total_received_rate),
            format_bytes(total_received)
        )
    };
    
    let totals = Paragraph::new(totals_text)
        .block(Block::default().borders(Borders::ALL).title("Network Totals"));
    f.render_widget(totals, area);
} 