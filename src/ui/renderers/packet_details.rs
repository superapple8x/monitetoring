use ratatui::{Frame, layout::{Constraint, Direction, Layout}, widgets::{Block, Borders, Row, Table, Cell, Paragraph}, style::{Style, Modifier, Color}, text::{Span, Line}};
use crate::types::{App, PacketDirection, PacketSortColumn, PacketSortDirection, PacketCacheMeta};


/// Terminal width thresholds for responsive layout
const NARROW_TERMINAL_THRESHOLD: u16 = 80;
const WIDE_TERMINAL_THRESHOLD: u16 = 120;

/// Thresholds for visual highlights
const LARGE_PACKET_THRESHOLD_BYTES: usize = 100_000; // Highlight packets larger than 100 KB
const FREQUENT_CONNECTION_THRESHOLD: usize = 20;     // Highlight connections with > 20 packets in current viewport

/// Common port to service name mappings for better readability
fn get_port_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-DATA"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("TELNET"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        3306 => Some("MYSQL"),
        5432 => Some("POSTGRES"),
        6379 => Some("REDIS"),
        8080 => Some("HTTP-ALT"),
        9200 => Some("ELASTIC"),
        _ => None,
    }
}

/// Format port with service name if known
fn format_port_with_service(port: u16) -> String {
    if let Some(service) = get_port_name(port) {
        format!("{}({})", port, service)
    } else {
        port.to_string()
    }
}

/// Get protocol color for better visual distinction
fn get_protocol_color(protocol: &str) -> Color {
    match protocol {
        "TCP" => Color::Red,
        "UDP" => Color::Green,
        "ICMP" => Color::Yellow,
        _ => Color::White,
    }
}

/// Smart endpoint formatting - prioritizes external/interesting endpoints
fn format_endpoint_smart(ip: &str, port: u16, is_localhost: bool) -> String {
    if is_localhost {
        // For localhost, just show the port with service name
        format!("localhost:{}", format_port_with_service(port))
    } else {
        // For external IPs, show IP:port with service name for common ports
        if let Some(service) = get_port_name(port) {
            format!("{}:{}", truncate_ip(ip, 15), service)
        } else {
            format!("{}:{}", truncate_ip(ip, 15), port)
        }
    }
}

/// Truncate IP address for space efficiency
fn truncate_ip(ip: &str, max_len: usize) -> String {
    if ip.len() <= max_len {
        ip.to_string()
    } else {
        format!("{}…", &ip[..max_len.saturating_sub(1)])
    }
}

/// Format connection with directional arrow and smart endpoint prioritization
fn format_connection_enhanced(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16, direction: PacketDirection) -> String {
    let src_is_localhost = src_ip.starts_with("127.0.0.1") || src_ip.starts_with("::1") || src_ip == "localhost";
    let dst_is_localhost = dst_ip.starts_with("127.0.0.1") || dst_ip.starts_with("::1") || dst_ip == "localhost";
    
    match direction {
        PacketDirection::Sent => {
            if dst_is_localhost {
                // Sending to localhost, show source as primary
                format_endpoint_smart(src_ip, src_port, src_is_localhost)
            } else {
                // Sending to external, show destination as primary
                format!("→{}", format_endpoint_smart(dst_ip, dst_port, dst_is_localhost))
            }
        }
        PacketDirection::Received => {
            if src_is_localhost {
                // Receiving from localhost, show destination as primary
                format_endpoint_smart(dst_ip, dst_port, dst_is_localhost)
            } else {
                // Receiving from external, show source as primary
                format!("←{}", format_endpoint_smart(src_ip, src_port, src_is_localhost))
            }
        }
    }
}

/// Calculate relative timestamp from the first packet in the list
fn format_relative_timestamp(current_time: std::time::SystemTime, base_time: Option<std::time::SystemTime>, use_relative: bool) -> String {
    if !use_relative {
        // Use absolute time format (existing behavior)
        let dt: chrono::DateTime<chrono::Local> = current_time.into();
        return dt.format("%H:%M:%S%.3f").to_string();
    }
    
    if let Some(base) = base_time {
        if let Ok(duration) = current_time.duration_since(base) {
            let secs = duration.as_secs_f64();
            if secs < 60.0 {
                format!("+{:.3}s", secs)
            } else if secs < 3600.0 {
                format!("+{:.1}m", secs / 60.0)
            } else {
                format!("+{:.1}h", secs / 3600.0)
            }
        } else {
            // Fallback to absolute time
            let dt: chrono::DateTime<chrono::Local> = current_time.into();
            dt.format("%H:%M:%S%.3f").to_string()
        }
    } else {
        // No base time, use absolute
        let dt: chrono::DateTime<chrono::Local> = current_time.into();
        dt.format("%H:%M:%S%.3f").to_string()
    }
}

/// Render per-packet details for the selected process
pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.size();
    let terminal_width = area.width;

    // FIXED FOOTER APPROACH: Always allocate space for export notification to prevent layout artifacts
    // This eliminates the dynamic layout changes that cause UI artifacts
    let chunks = if app.packet_search_mode {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Status/help line
                Constraint::Length(3), // Search input bar
                Constraint::Min(0),    // Main table
                Constraint::Length(4), // Export notification (ALWAYS allocated)
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Status/help line
                Constraint::Min(0),    // Main table
                Constraint::Length(4), // Export notification (ALWAYS allocated)
            ])
            .split(area)
    };

    let mut chunk_idx = 0;

    // If no process is selected, just display a message
    let pid = match app.selected_process {
        Some(pid) => pid,
        None => {
            let help_text = Paragraph::new("No process selected. Go back to main view and select a process to see packet details.")
                .block(Block::default().title("Packet Details").borders(Borders::ALL))
                .style(Style::default().fg(Color::Yellow));
            f.render_widget(help_text, area);
            return;
        }
    };

    // Before borrowing process_info immutably, ensure the packet cache is up-to-date.
    // This avoids overlapping mutable and immutable borrows of `app`.
    ensure_packet_cache(app, pid);

    // After cache is ensured, we can safely take an immutable reference for rendering.
    let process_info = app.stats.get(&pid).expect("process should exist");

    let total_packets = process_info.packet_history.len();
    let filtered_count = app.packet_cache.len();

    // Render status line with filtering info and navigation hints
    let filter_info = if let Some(filter) = &app.packet_filter {
        let mut parts: Vec<String> = Vec::new();
        
        if let Some(proto) = filter.protocol {
            let proto_str = match proto {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                1 => "ICMP".to_string(),
                other => format!("Proto {}", other),
            };
            parts.push(proto_str);
        }
        
        if let Some(dir) = filter.direction {
            let dir_str = match dir {
                PacketDirection::Sent => "Sent".to_string(),
                PacketDirection::Received => "Received".to_string(),
            };
            parts.push(dir_str);
        }
        
        if let Some(search) = &filter.search_term {
            parts.push(format!("\"{}\"", search));
        }
        
        if parts.is_empty() {
            String::new()
        } else {
            format!("Filter: {} | ", parts.join(" "))
        }
    } else {
        String::new()
    };

    // Sort indicator
    let sort_info = {
        let column_name = match app.packet_sort_column {
            PacketSortColumn::Timestamp => "Time",
            PacketSortColumn::Direction => "Dir", 
            PacketSortColumn::Protocol => "Proto",
            PacketSortColumn::SourceIp => "Source",
            PacketSortColumn::SourcePort => "SrcPort",
            PacketSortColumn::DestIp => "Dest",
            PacketSortColumn::DestPort => "DstPort",
            PacketSortColumn::Size => "Size",
        };
        let direction_arrow = match app.packet_sort_direction {
            PacketSortDirection::Asc => "↑",
            PacketSortDirection::Desc => "↓",
        };
        format!("Sort: {}{} | ", column_name, direction_arrow)
    };

    // Simple header title without packet count (packet count goes to table header)
    let header_title = format!("Packet Details - {} (PID {})", process_info.name, pid);

    // Status line now focuses on controls and filtering info - made more compact for smaller terminals
    let status_text = if filtered_count == 0 {
        if total_packets == 0 {
            "Network activity will appear here in real-time.".to_string()
        } else {
            format!("{}No packets match current filter", filter_info)
        }
    } else {
        if terminal_width < NARROW_TERMINAL_THRESHOLD {
            // Compact controls for narrow terminals
            format!("{}{}↑↓:scroll /:search e:export Esc:back", filter_info, sort_info)
        } else {
            // Full controls for wider terminals
            format!("{}{}Controls: ↑↓:scroll PgUp/PgDn:page 1-6:sort /:search e:export Esc:back", 
                    filter_info, sort_info)
        }
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(status_text, Style::default().fg(if filtered_count == 0 { Color::Yellow } else { Color::Cyan }))
    ]))
    .block(Block::default().title(header_title).borders(Borders::ALL));
    
    f.render_widget(status, chunks[chunk_idx]);
    chunk_idx += 1;

    // Render search input bar if in search mode
    if app.packet_search_mode {
        let search_text = format!("Search: {}", app.packet_search_input);
        let search_bar = Paragraph::new(search_text)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Search (Enter: apply, Esc: cancel)"));
        f.render_widget(search_bar, chunks[chunk_idx]);
        chunk_idx += 1;
    }

    // If no packets to show, we're done
    if filtered_count == 0 {
        return;
    }

    let scroll_offset = app.packet_scroll_offset.min(filtered_count.saturating_sub(1));
    let visible_height = chunks[chunk_idx].height.saturating_sub(2) as usize; // minus borders & header
    app.packet_visible_rows = visible_height; // for PageUp/PageDown

    let end_idx = (scroll_offset + visible_height).min(filtered_count);

    // Build rows with responsive layout (narrow / medium / wide)
    let (rows, header, constraints) = build_responsive_table_data(
        app,
        process_info,
        scroll_offset,
        end_idx,
        terminal_width,
    );

    // Create table title with packet count information
    let table_title = if filtered_count == 0 {
        if total_packets == 0 {
            "Packets - No packets captured".to_string()
        } else {
            format!("Packets - No matches ({} total)", total_packets)
        }
    } else {
        let visible_start = app.packet_scroll_offset + 1;
        let visible_end = (app.packet_scroll_offset + visible_height).min(filtered_count);
        if terminal_width < NARROW_TERMINAL_THRESHOLD {
            // Compact title for narrow terminals
            format!("Packets {}-{}/{}", visible_start, visible_end, filtered_count)
        } else {
            format!("Packets - Showing {}-{} of {}", visible_start, visible_end, filtered_count)
        }
    };

    let table = Table::new(rows, &constraints)
        .header(header)
        .block(Block::default().title(table_title).borders(Borders::ALL));

    f.render_widget(table, chunks[chunk_idx]);

    // ALWAYS render the footer area (fixed space allocated) to prevent layout artifacts
    let export_notification_index = if app.packet_search_mode { 3 } else { 2 };
    
    match &app.export_notification_state {
        crate::types::NotificationState::Active(export_msg) => {
            // Show export notification
            let export_notification = Paragraph::new(export_msg.clone())
                .style(Style::default().fg(Color::Green))
                .block(Block::default()
                    .title("Export Status")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green)));
            
            f.render_widget(export_notification, chunks[export_notification_index]);
        }
        crate::types::NotificationState::Expiring => {
            // Show fading notification during cleanup
            let fading_notification = Paragraph::new("Notification clearing...")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::NONE));
            
            f.render_widget(fading_notification, chunks[export_notification_index]);
        }
        crate::types::NotificationState::None => {
            // Show empty footer space to maintain consistent layout
            let empty_footer = Paragraph::new("")
                .block(Block::default().borders(Borders::NONE));
            
            f.render_widget(empty_footer, chunks[export_notification_index]);
        }
    }
}

/// Build table data (rows, header, constraints) based on terminal width
fn build_responsive_table_data<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
    terminal_width: u16,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    
    if terminal_width < NARROW_TERMINAL_THRESHOLD {
        // Narrow terminal layout: Time, Proto+Dir, Connection, Size
        build_narrow_layout(app, process_info, scroll_offset, end_idx)
    } else if terminal_width < WIDE_TERMINAL_THRESHOLD {
        // Medium terminal layout: Current layout with adjustments
        build_medium_layout(app, process_info, scroll_offset, end_idx)
    } else {
        // Wide terminal layout: Enhanced with better proportions
        build_wide_layout(app, process_info, scroll_offset, end_idx)
    }
}

/// Narrow terminal layout (< 80 chars)
fn build_narrow_layout<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    
    // Get base timestamp for relative timing (first packet in current view)
    let base_time = if !process_info.packet_history.is_empty() {
        Some(process_info.packet_history[0].timestamp)
    } else {
        None
    };
    
    // Build frequency map for connection counts within the visible slice
    let slice = &app.packet_cache[scroll_offset..end_idx];
    let mut conn_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for &packet_idx in slice {
        let p = &process_info.packet_history[packet_idx];
        let key = format!("{}:{}-{}:{}-{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.protocol);
        *conn_counts.entry(key).or_insert(0) += 1;
    }
    
    let mut rows: Vec<Row> = Vec::with_capacity(slice.len());
    let mut last_conn_key: Option<String> = None;
    let mut bg_toggle = false;
    
    for &packet_idx in slice {
        let p = &process_info.packet_history[packet_idx];
        let conn_key = format!("{}:{}-{}:{}-{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.protocol);
        if last_conn_key.as_ref().map(|k| k != &conn_key).unwrap_or(true) {
            bg_toggle = !bg_toggle;
            last_conn_key = Some(conn_key.clone());
        }
        
        let row_style = if bg_toggle { Style::default() } else { Style::default().bg(Color::DarkGray) };
        
        // Timestamp (potentially truncated already outside loop)
        let timestamp = format_relative_timestamp(p.timestamp, base_time, true);
        
        // Direction + protocol combined string e.g., ↑TCP
        let proto_dir_str = match p.direction {
            PacketDirection::Sent => format!("↑{}", p.cached_proto),
            PacketDirection::Received => format!("↓{}", p.cached_proto),
        };
        let proto_color = get_protocol_color(&p.cached_proto);
        let proto_cell = Cell::from(Span::styled(proto_dir_str, Style::default().fg(proto_color).add_modifier(Modifier::BOLD)));

        // Connection summary
        let connection_summary = format_connection_enhanced(
            &p.src_ip.to_string(),
            p.src_port,
            &p.dst_ip.to_string(),
            p.dst_port,
            p.direction,
        );
        let frequent = conn_counts.get(&conn_key).copied().unwrap_or(0) > FREQUENT_CONNECTION_THRESHOLD;
        let connection_cell = if frequent {
            Cell::from(Span::styled(connection_summary, Style::default().fg(Color::LightCyan)))
        } else {
            Cell::from(connection_summary)
        };
        
        // Size cell highlight
        let size_cell = if p.size > LARGE_PACKET_THRESHOLD_BYTES {
            Cell::from(Span::styled(p.cached_size.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
        } else {
            Cell::from(p.cached_size.clone())
        };
        
        let row = Row::new(vec![
            Cell::from(timestamp),
            proto_cell,
            connection_cell,
            size_cell,
        ]).style(row_style);
        rows.push(row);
    }

    // Compact headers for narrow terminals
    let header = Row::new(vec![
        Cell::from(Span::styled(
            format!("1.Time{}", get_sort_indicator(app, PacketSortColumn::Timestamp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("2.P/D{}", get_combined_sort_indicator(app, PacketSortColumn::Protocol, PacketSortColumn::Direction)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("3.Connection{}", get_combined_sort_indicator(app, PacketSortColumn::SourceIp, PacketSortColumn::DestIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("4.Size{}", get_sort_indicator(app, PacketSortColumn::Size)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
    ]);

    let constraints = vec![
        Constraint::Length(8),   // Time (HH:MM:SS)
        Constraint::Length(6),   // Proto+Dir
        Constraint::Min(20),     // Connection
        Constraint::Length(8),   // Size
    ];

    (rows, header, constraints)
}

/// Medium terminal layout (80-120 chars)
fn build_medium_layout<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    
    // Build frequency map & rows with enhanced visual hierarchy
    let slice = &app.packet_cache[scroll_offset..end_idx];
    let mut conn_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for &packet_idx in slice {
        let pkt = &process_info.packet_history[packet_idx];
        let key = format!("{}:{}-{}:{}-{}", pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol);
        *conn_counts.entry(key).or_insert(0) += 1;
    }

    let mut rows: Vec<Row> = Vec::with_capacity(slice.len());
    let mut last_conn_key: Option<String> = None;
    let mut bg_toggle = false;

    for &packet_idx in slice {
        let p = &process_info.packet_history[packet_idx];
        let conn_key = format!("{}:{}-{}:{}-{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.protocol);
        if last_conn_key.as_ref().map(|k| k != &conn_key).unwrap_or(true) {
            bg_toggle = !bg_toggle;
            last_conn_key = Some(conn_key.clone());
        }

        let row_style = if bg_toggle { Style::default() } else { Style::default().bg(Color::DarkGray) };

        let timestamp = if p.cached_ts.len() > 12 { &p.cached_ts[..12] } else { &p.cached_ts };
        let dir_str = match p.direction { PacketDirection::Sent => "↑", PacketDirection::Received => "↓" };
        let proto_color = get_protocol_color(&p.cached_proto);
        let proto_cell = Cell::from(Span::styled(p.cached_proto.clone(), Style::default().fg(proto_color).add_modifier(Modifier::BOLD)));

        let enhanced_src = format_endpoint_smart(&p.src_ip.to_string(), p.src_port, p.src_ip.to_string().starts_with("127.0.0.1") || p.src_ip.to_string().starts_with("::1"));
        let enhanced_dst = format_endpoint_smart(&p.dst_ip.to_string(), p.dst_port, p.dst_ip.to_string().starts_with("127.0.0.1") || p.dst_ip.to_string().starts_with("::1"));
        let frequent = conn_counts.get(&conn_key).copied().unwrap_or(0) > FREQUENT_CONNECTION_THRESHOLD;
        let src_cell = if frequent { Cell::from(Span::styled(enhanced_src, Style::default().fg(Color::LightCyan))) } else { Cell::from(enhanced_src) };
        let dst_cell = if frequent { Cell::from(Span::styled(enhanced_dst, Style::default().fg(Color::LightCyan))) } else { Cell::from(enhanced_dst) };

        let size_cell = if p.size > LARGE_PACKET_THRESHOLD_BYTES {
            Cell::from(Span::styled(p.cached_size.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
        } else { Cell::from(p.cached_size.clone()) };

        rows.push(Row::new(vec![
            Cell::from(timestamp),
            Cell::from(dir_str.to_string()),
            proto_cell,
            src_cell,
            dst_cell,
            size_cell,
        ]).style(row_style));
    }

    // Current headers with improved spacing
    let header = Row::new(vec![
        Cell::from(Span::styled(
            format!("1.Time{}", get_sort_indicator(app, PacketSortColumn::Timestamp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("2.Dir{}", get_sort_indicator(app, PacketSortColumn::Direction)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("3.Proto{}", get_sort_indicator(app, PacketSortColumn::Protocol)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("4.Source{}", get_sort_indicator(app, PacketSortColumn::SourceIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("5.Dest{}", get_sort_indicator(app, PacketSortColumn::DestIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("6.Size{}", get_sort_indicator(app, PacketSortColumn::Size)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
    ]);

    let constraints = vec![
        Constraint::Length(12),  // Time (shorter than before)
        Constraint::Length(5),   // Dir (fixed from 4 to 5 to avoid truncation)
        Constraint::Length(6),   // Proto
        Constraint::Percentage(28), // Source
        Constraint::Percentage(28), // Dest
        Constraint::Length(10),  // Size
    ];

    (rows, header, constraints)
}

/// Wide terminal layout (>= 120 chars)
fn build_wide_layout<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    
    // Build rows with connection grouping & highlights
    let slice = &app.packet_cache[scroll_offset..end_idx];
    let mut conn_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for &idx in slice {
        let p = &process_info.packet_history[idx];
        let key = format!("{}:{}-{}:{}-{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.protocol);
        *conn_counts.entry(key).or_insert(0) += 1;
    }

    let mut rows: Vec<Row> = Vec::with_capacity(slice.len());
    let mut last_conn_key: Option<String> = None;
    let mut bg_toggle = false;

    for &packet_idx in slice {
        let p = &process_info.packet_history[packet_idx];
        let conn_key = format!("{}:{}-{}:{}-{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.protocol);
        if last_conn_key.as_ref().map(|k| k != &conn_key).unwrap_or(true) {
            bg_toggle = !bg_toggle;
            last_conn_key = Some(conn_key.clone());
        }

        let mut style = if bg_toggle { Style::default() } else { Style::default().bg(Color::DarkGray) };
        // direction tint
        style = match p.direction { PacketDirection::Sent => style.fg(Color::LightBlue), PacketDirection::Received => style.fg(Color::LightGreen) };

        let timestamp = p.cached_ts.as_str();
        let dir_str = match p.direction { PacketDirection::Sent => "↑ OUT", PacketDirection::Received => "↓ IN" };
        let proto_color = get_protocol_color(&p.cached_proto);

        let enhanced_src = format_endpoint_smart(&p.src_ip.to_string(), p.src_port, p.src_ip.to_string().starts_with("127.0.0.1") || p.src_ip.to_string().starts_with("::1"));
        let enhanced_dst = format_endpoint_smart(&p.dst_ip.to_string(), p.dst_port, p.dst_ip.to_string().starts_with("127.0.0.1") || p.dst_ip.to_string().starts_with("::1"));

        let frequent = conn_counts.get(&conn_key).copied().unwrap_or(0) > FREQUENT_CONNECTION_THRESHOLD;
        let src_cell = if frequent { Cell::from(Span::styled(enhanced_src, Style::default().fg(Color::LightCyan))) } else { Cell::from(enhanced_src) };
        let dst_cell = if frequent { Cell::from(Span::styled(enhanced_dst, Style::default().fg(Color::LightCyan))) } else { Cell::from(enhanced_dst) };

        let size_cell = if p.size > LARGE_PACKET_THRESHOLD_BYTES {
            Cell::from(Span::styled(p.cached_size.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
        } else { Cell::from(p.cached_size.clone()) };

        rows.push(Row::new(vec![
            Cell::from(timestamp),
            Cell::from(Span::styled(dir_str.to_string(), Style::default().add_modifier(Modifier::BOLD))),
            Cell::from(Span::styled(p.cached_proto.clone(), Style::default().fg(proto_color).add_modifier(Modifier::BOLD))),
            src_cell,
            dst_cell,
            size_cell,
        ]).style(style));
    }

    // Enhanced headers for wide terminals
    let header = Row::new(vec![
        Cell::from(Span::styled(
            format!("1.Timestamp{}", get_sort_indicator(app, PacketSortColumn::Timestamp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("2.Direction{}", get_sort_indicator(app, PacketSortColumn::Direction)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("3.Protocol{}", get_sort_indicator(app, PacketSortColumn::Protocol)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("4.Source{}", get_sort_indicator(app, PacketSortColumn::SourceIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("5.Destination{}", get_sort_indicator(app, PacketSortColumn::DestIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("6.Size{}", get_sort_indicator(app, PacketSortColumn::Size)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
    ]);

    let constraints = vec![
        Constraint::Length(15),  // Full timestamp
        Constraint::Length(7),   // Direction (↑ OUT / ↓ IN)
        Constraint::Length(8),   // Protocol
        Constraint::Percentage(27), // Source (enhanced with service names)
        Constraint::Percentage(27), // Destination (enhanced with service names)  
        Constraint::Length(12),  // Size
    ];

    (rows, header, constraints)
}

/// Helper function to get sort indicator for a column
fn get_sort_indicator(app: &App, column: PacketSortColumn) -> String {
    if app.packet_sort_column == column {
        match app.packet_sort_direction {
            PacketSortDirection::Asc => "↑".to_string(),
            PacketSortDirection::Desc => "↓".to_string(),
        }
    } else {
        String::new()
    }
}

/// Helper function to get combined sort indicator for multiple columns
fn get_combined_sort_indicator(app: &App, col1: PacketSortColumn, col2: PacketSortColumn) -> String {
    if app.packet_sort_column == col1 || app.packet_sort_column == col2 {
        match app.packet_sort_direction {
            PacketSortDirection::Asc => "↑".to_string(),
            PacketSortDirection::Desc => "↓".to_string(),
        }
    } else {
        String::new()
    }
}

/// Export packets to CSV file
pub fn export_packets_to_csv(app: &mut App, process_info: &crate::types::ProcessInfo, _pid: i32) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Write;
    use std::env;
    use std::time::Instant;
    
    // Create filename with timestamp
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("packets_{}_{}.csv", process_info.name.replace(" ", "_"), timestamp);
    
    // Get current directory for display
    let current_dir = env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "current directory".to_string());
    
    let mut file = File::create(&filename)?;
    
    // Write CSV header
    writeln!(file, "Timestamp,Direction,Protocol,Source_IP,Source_Port,Dest_IP,Dest_Port,Size_Bytes")?;
    
    // Apply same filtering logic as the UI
    let filtered_packets: Vec<_> = process_info.packet_history.iter().filter(|p| {
        if let Some(filter) = &app.packet_filter {
            if let Some(proto) = filter.protocol {
                if p.protocol != proto { return false; }
            }
            if let Some(dir) = filter.direction {
                if p.direction != dir { return false; }
            }
            if let Some(re) = &filter.search_regex {
                let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                if !re.is_match(&search_text) { return false; }
            } else if let Some(term) = &filter.search_term {
                let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port).to_lowercase();
                if !search_text.contains(term) { return false; }
            }
        }
        true
    }).collect();
    
    let packet_count = filtered_packets.len();
    
    // Write packet data
    for packet in filtered_packets {
        let ts: chrono::DateTime<chrono::Local> = packet.timestamp.into();
        let direction = match packet.direction {
            PacketDirection::Sent => "Sent",
            PacketDirection::Received => "Received",
        };
        let protocol: String = match packet.protocol {
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            1 => "ICMP".to_string(),
            other => other.to_string(),
        };
        
        writeln!(
            file,
            "{},{},{},{},{},{},{},{}",
            ts.format("%Y-%m-%d %H:%M:%S%.3f"),
            direction,
            protocol,
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.size
        )?;
    }
    
    // Set export notification with detailed information
    let full_path = std::path::Path::new(&current_dir).join(&filename);
    let export_msg = format!(
        "✓ Successfully exported {} packets to:\n{}\n\nFile: {}",
        packet_count,
        current_dir,
        filename
    );
    
    app.export_notification_state = crate::types::NotificationState::Active(export_msg);
    app.export_notification_time = Some(Instant::now());
    
    eprintln!("Exported {} packets to: {}", packet_count, full_path.display());
    Ok(())
}

/// Ensure that `app.packet_cache` contains indices of packets that satisfy the
/// current filter & sort settings. Rebuilds the vector only when something has
/// changed (filter, sort, history length, or selected PID).
fn ensure_packet_cache(app: &mut App, pid: i32) {
    let Some(process_info) = app.stats.get(&pid) else {
        return;
    };

    let history_len = process_info.packet_history.len();

    let cache_is_valid = if let Some(meta) = &app.packet_cache_meta {
        meta.pid == pid
            && meta.history_len == history_len
            && filters_equal(&meta.filter, &app.packet_filter)
            && meta.sort_column == app.packet_sort_column
            && meta.sort_direction == app.packet_sort_direction
    } else { false };

    if cache_is_valid {
        return;
    }

    // Rebuild cache
    let mut indices: Vec<usize> = (0..history_len).collect();

    // Apply filter
    indices.retain(|&idx| {
        let p = &process_info.packet_history[idx];
        if let Some(filter) = &app.packet_filter {
            if let Some(proto) = filter.protocol {
                if p.protocol != proto { return false; }
            }
            if let Some(dir) = filter.direction {
                if p.direction != dir { return false; }
            }
            if let Some(re) = &filter.search_regex {
                let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                if !re.is_match(&search_text) { return false; }
            } else if let Some(term) = &filter.search_term {
                let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port).to_lowercase();
                if !search_text.contains(term) { return false; }
            }
        }
        true
    });

    // Sort indices
    indices.sort_by(|&a_idx, &b_idx| {
        let a = &process_info.packet_history[a_idx];
        let b = &process_info.packet_history[b_idx];
        let cmp = match app.packet_sort_column {
            PacketSortColumn::Timestamp => a.timestamp.cmp(&b.timestamp),
            PacketSortColumn::Direction => a.direction.cmp(&b.direction),
            PacketSortColumn::Protocol => a.protocol.cmp(&b.protocol),
            PacketSortColumn::SourceIp => a.src_ip.cmp(&b.src_ip),
            PacketSortColumn::SourcePort => a.src_port.cmp(&b.src_port),
            PacketSortColumn::DestIp => a.dst_ip.cmp(&b.dst_ip),
            PacketSortColumn::DestPort => a.dst_port.cmp(&b.dst_port),
            PacketSortColumn::Size => a.size.cmp(&b.size),
        };
        match app.packet_sort_direction {
            PacketSortDirection::Asc => cmp,
            PacketSortDirection::Desc => cmp.reverse(),
        }
    });

    // Update app state
    app.packet_cache = indices;
    app.packet_cache_meta = Some(PacketCacheMeta {
        pid,
        filter: app.packet_filter.clone(),
        sort_column: app.packet_sort_column,
        sort_direction: app.packet_sort_direction,
        history_len,
    });
}

/// Compare PacketFilter instances manually since regex::Regex doesn't implement PartialEq
fn filters_equal(a: &Option<crate::types::PacketFilter>, b: &Option<crate::types::PacketFilter>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(fa), Some(fb)) => {
            fa.protocol == fb.protocol
                && fa.direction == fb.direction
                && fa.search_term == fb.search_term
                // For regex, we compare the pattern strings when both exist
                && match (&fa.search_regex, &fb.search_regex) {
                    (None, None) => true,
                    (Some(ra), Some(rb)) => ra.as_str() == rb.as_str(),
                    _ => false,
                }
        }
        _ => false,
    }
} 