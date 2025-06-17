use ratatui::{
    widgets::{Block, Borders, Paragraph, Table, Row, Cell, Gauge, BarChart, Bar, BarGroup, List, ListItem, ListState},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    text::{Line, Span, Text},
    Frame
};
use crate::types::App;
use crate::ui::utils::format_bytes;

/// Render the system overview mode with dashboard metrics
pub fn render(f: &mut Frame, app: &App) {
    // Main layout: Title (with navigation) + Dashboard + Alerts
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // Title (header with navigation)
            Constraint::Min(0),     // Main dashboard area
            Constraint::Length(6),  // Alert progress bars section
        ])
        .split(f.size());

    render_title(f, app, main_chunks[0]);
    render_dashboard(f, app, main_chunks[1]);
    render_alert_progress(f, app, main_chunks[2]);
}

/// Render the title header with navigation inside
fn render_title(f: &mut Frame, _app: &App, area: ratatui::layout::Rect) {
    // Create block first
    let block = Block::default().title("System Overview Dashboard").borders(Borders::ALL);
    // Get inner rect before moving ownership of block
    let inner = block.inner(area);
    // Render the outer block (moves ownership)
    f.render_widget(block, area);

    // Navigation guide paragraph rendered inside the block
    let nav_text = "q: quit | Tab: switch mode | +/-: adjust quota | r: reset";
    let nav_paragraph = Paragraph::new(nav_text);
    f.render_widget(nav_paragraph, inner);
}

/// Render the main dashboard area with gauge, charts, and system info
fn render_dashboard(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Split main area vertically: gauge on top, protocol section below
    let dashboard_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),  // Bandwidth gauge on top
            Constraint::Min(0),     // Protocol section with integrated system info
        ])
        .split(area);
        
    render_bandwidth_gauge(f, app, dashboard_chunks[0]);
    render_protocol_section(f, app, dashboard_chunks[1]);
}

/// Render the bandwidth usage gauge
fn render_bandwidth_gauge(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (total_sent, total_received, total_sent_rate, total_received_rate) = app.totals();
    let total_bandwidth = total_sent + total_received;
    let total_rate = total_sent_rate + total_received_rate;
    
    let quota_ratio = (total_bandwidth as f64 / app.total_quota_threshold as f64).min(1.0);
    let quota_exceeded = total_bandwidth > app.total_quota_threshold;
    
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
    f.render_widget(bandwidth_gauge, area);
}

/// Render the protocol distribution section
fn render_protocol_section(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Draw outer block for protocol distribution/breakdown
    let proto_block = Block::default().title("Protocol Distribution & System Info").borders(Borders::ALL);
    let proto_inner = proto_block.inner(area);
    f.render_widget(proto_block, area);

    // Split inner area: chart left, table and system info right
    let protocol_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(60), // Chart area
            Constraint::Percentage(40), // Table + System info area on right
        ])
        .split(proto_inner);

    render_protocol_chart(f, app, protocol_chunks[0]);
    
    // Split right area vertically: table top, system info bottom
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(70), // Protocol table
            Constraint::Percentage(30), // System info
        ])
        .split(protocol_chunks[1]);
    
    render_protocol_table(f, app, right_chunks[0]);
    render_system_info(f, app, right_chunks[1]);
}

/// Render the protocol distribution bar chart
fn render_protocol_chart(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (_, _, total_sent_rate, total_received_rate) = app.totals();
    let total_rate = total_sent_rate + total_received_rate;
    
    // Use current rates if non-zero, otherwise fall back to last non-zero rates for display persistence
    let (display_tcp, display_udp, display_icmp, display_other) = if total_rate > 0 {
        (app.system_stats.tcp_rate, app.system_stats.udp_rate, 
         app.system_stats.icmp_rate, app.system_stats.other_rate)
    } else {
        // Use last non-zero rates with reduced opacity to indicate they're historical
        (app.last_nonzero_system_stats.tcp_rate / 4, app.last_nonzero_system_stats.udp_rate / 4,
         app.last_nonzero_system_stats.icmp_rate / 4, app.last_nonzero_system_stats.other_rate / 4)
    };
    
    let max_protocol_rate = [display_tcp, display_udp, display_icmp, display_other]
        .iter().max().copied().unwrap_or(1).max(1); // Ensure minimum of 1 for scaling
    
    let bars: Vec<Bar<'_>> = vec![
        Bar::default()
            .value(display_tcp)
            .label("TCP".into())
            .text_value(String::new()) // hide numeric value
            .style(Style::default().fg(if total_rate > 0 { Color::Red } else { Color::DarkGray })),
        Bar::default()
            .value(display_udp)
            .label("UDP".into())
            .text_value(String::new())
            .style(Style::default().fg(if total_rate > 0 { Color::Green } else { Color::DarkGray })),
        Bar::default()
            .value(display_icmp)
            .label("ICMP".into())
            .text_value(String::new())
            .style(Style::default().fg(if total_rate > 0 { Color::Yellow } else { Color::DarkGray })),
        Bar::default()
            .value(display_other)
            .label("Other".into())
            .text_value(String::new())
            .style(Style::default().fg(if total_rate > 0 { Color::Magenta } else { Color::DarkGray })),
    ];

    let bar_group = BarGroup::default().bars(&bars);

    let protocol_chart = BarChart::default()
        .data(bar_group)
        .bar_width(12)
        .bar_gap(2)
        .max(max_protocol_rate)
        .value_style(Style::default().fg(Color::Black)) // Hidden
        .label_style(Style::default().fg(Color::White));
    f.render_widget(protocol_chart, area);
}

/// Render the protocol breakdown table
fn render_protocol_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (_, _, total_sent_rate, total_received_rate) = app.totals();
    let total_rate = total_sent_rate + total_received_rate;
    
    // Use current rates if non-zero, otherwise fall back to last non-zero rates for display persistence
    let (display_tcp, display_udp, display_icmp, display_other) = if total_rate > 0 {
        (app.system_stats.tcp_rate, app.system_stats.udp_rate, 
         app.system_stats.icmp_rate, app.system_stats.other_rate)
    } else {
        (app.last_nonzero_system_stats.tcp_rate, app.last_nonzero_system_stats.udp_rate,
         app.last_nonzero_system_stats.icmp_rate, app.last_nonzero_system_stats.other_rate)
    };
    
    let display_total = display_tcp + display_udp + display_icmp + display_other;
    
    let protocol_rows: Vec<Row> = vec![
        Row::new(vec![
            Cell::from(Span::styled("■ TCP", Style::default().fg(if total_rate > 0 { Color::Red } else { Color::DarkGray }).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(display_tcp)),
            Cell::from(app.system_stats.tcp_packets.to_string()),
            Cell::from(format!("{:.1}%", if display_total > 0 { (display_tcp as f64 / display_total as f64) * 100.0 } else { 0.0 })),
        ]),
        Row::new(vec![
            Cell::from(Span::styled("■ UDP", Style::default().fg(if total_rate > 0 { Color::Green } else { Color::DarkGray }).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(display_udp)),
            Cell::from(app.system_stats.udp_packets.to_string()),
            Cell::from(format!("{:.1}%", if display_total > 0 { (display_udp as f64 / display_total as f64) * 100.0 } else { 0.0 })),
        ]),
        Row::new(vec![
            Cell::from(Span::styled("■ ICMP", Style::default().fg(if total_rate > 0 { Color::Yellow } else { Color::DarkGray }).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(display_icmp)),
            Cell::from(app.system_stats.icmp_packets.to_string()),
            Cell::from(format!("{:.1}%", if display_total > 0 { (display_icmp as f64 / display_total as f64) * 100.0 } else { 0.0 })),
        ]),
        Row::new(vec![
            Cell::from(Span::styled("■ Other", Style::default().fg(if total_rate > 0 { Color::Magenta } else { Color::DarkGray }).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(display_other)),
            Cell::from(app.system_stats.other_packets.to_string()),
            Cell::from(format!("{:.1}%", if display_total > 0 { (display_other as f64 / display_total as f64) * 100.0 } else { 0.0 })),
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
    
    f.render_widget(protocol_table, area);
}

/// Render system information panel (compact version)
fn render_system_info(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let uptime = app.start_time.elapsed();
    let uptime_text = format!("{}h{}m", 
        uptime.as_secs() / 3600,
        (uptime.as_secs() % 3600) / 60);
    
    let process_count = app.stats.len();
    let active_alerts = app.alerts.len();
    
    let (total_sent, total_received, _, _) = app.totals();
    let total_bandwidth = total_sent + total_received;
    let quota_exceeded = total_bandwidth > app.total_quota_threshold;
    
    let threshold_status = if quota_exceeded { "EXCEEDED!" } else { "Normal" };
    let threshold_color = if quota_exceeded { Color::Red } else { Color::Green };
    
    let info_text = vec![
        Line::from(format!("Up: {} | Proc: {} | Alerts: {}", uptime_text, process_count, active_alerts)),
        Line::from(vec![
            Span::raw("Quota: "),
            Span::styled(threshold_status, Style::default().fg(threshold_color).add_modifier(Modifier::BOLD)),
        ]),
    ];

    let info_paragraph = Paragraph::new(Text::from(info_text))
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(info_paragraph, area);
}

/// Render alert progress bars section (scrollable)
fn render_alert_progress(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    if !app.alerts.is_empty() {
        let alert_items: Vec<ListItem> = app.alerts.iter()
            .filter_map(|(pid, alert)| {
                if let Some(process_info) = app.stats.get(pid) {
                    let current_usage = process_info.sent + process_info.received;
                    let progress = (current_usage as f64 / alert.threshold_bytes as f64).min(1.0);
                    let progress_percent = (progress * 100.0) as usize;
                    
                    let bar_length = 15; // Reduced from 20 to save space
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

                    // More compact format: name (truncated if needed), bar, percentage
                    let name = if process_info.name.len() > 12 {
                        format!("{}...", &process_info.name[..9])
                    } else {
                        process_info.name.clone()
                    };

                    Some(ListItem::new(Line::from(vec![
                        Span::raw(format!("{:12} ", name)), // Fixed width for alignment
                        Span::styled(format!("[{}] {:3}%", bar, progress_percent), Style::default().fg(color)),
                    ])))
                } else {
                    None
                }
            })
            .collect();

        if !alert_items.is_empty() {
            let alert_count = alert_items.len();
            let alert_list = List::new(alert_items)
                .block(Block::default().title(format!("Alert Thresholds ({})", alert_count)).borders(Borders::ALL));
            
            // Create a mutable list state for scrolling
            let mut list_state = ListState::default();
            list_state.select(Some(app.alert_scroll_offset));
            
            f.render_stateful_widget(alert_list, area, &mut list_state);
        }
    } else {
        let no_alerts = Paragraph::new("No alert thresholds configured")
            .block(Block::default().title("Alert Thresholds").borders(Borders::ALL));
        f.render_widget(no_alerts, area);
    }
} 