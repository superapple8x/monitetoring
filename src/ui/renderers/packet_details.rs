use ratatui::{Frame, layout::{Constraint, Direction, Layout}, widgets::{Block, Borders, Row, Table, Cell, Paragraph}, style::{Style, Modifier, Color}, text::{Span, Line}};
use crate::types::{App, PacketDirection, PacketSortColumn, PacketSortDirection, PacketCacheMeta};

/// Render per-packet details for the selected process
pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.size();

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

    // Status line now focuses on controls and filtering info
    let status_text = if filtered_count == 0 {
        if total_packets == 0 {
            "Network activity will appear here in real-time.".to_string()
        } else {
            format!("{}No packets match current filter", filter_info)
        }
    } else {
        format!("{}{}Controls: ↑↓:scroll PgUp/PgDn:page 1-6:sort /:search e:export Esc:back", 
                filter_info, sort_info)
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

    // Build rows only for visible indices – no intermediate packet vector
    let rows: Vec<Row> = app.packet_cache[scroll_offset..end_idx]
        .iter()
        .enumerate()
        .map(|(i, &packet_idx)| {
            let p = &process_info.packet_history[packet_idx];
            let global_idx = scroll_offset + i;
            let ts_str = &p.cached_ts;
            let dir_str = match p.direction {
                PacketDirection::Sent => "↑",  // Up arrow for sent
                PacketDirection::Received => "↓",  // Down arrow for received
            };
            let proto_str = &p.cached_proto;

            // Alternate row colors for better readability
            let style = if global_idx % 2 == 0 {
                Style::default()
            } else {
                Style::default().bg(Color::DarkGray)
            };

            Row::new(vec![
                ts_str.clone(),
                dir_str.to_string(),
                proto_str.clone(),
                p.cached_src.clone(),
                p.cached_dst.clone(),
                p.cached_size.clone(),
            ]).style(style)
        }).collect();

    // Enhanced headers with sort indicators and column numbers
    let header = Row::new(vec![
        Cell::from(Span::styled(
            format!("1.Time{}", if app.packet_sort_column == PacketSortColumn::Timestamp {
                match app.packet_sort_direction { PacketSortDirection::Asc => "↑", PacketSortDirection::Desc => "↓" }
            } else { "" }),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("2.Dir{}", if app.packet_sort_column == PacketSortColumn::Direction {
                match app.packet_sort_direction { PacketSortDirection::Asc => "↑", PacketSortDirection::Desc => "↓" }
            } else { "" }),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("3.Proto{}", if app.packet_sort_column == PacketSortColumn::Protocol {
                match app.packet_sort_direction { PacketSortDirection::Asc => "↑", PacketSortDirection::Desc => "↓" }
            } else { "" }),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("4.Source{}", if app.packet_sort_column == PacketSortColumn::SourceIp {
                match app.packet_sort_direction { PacketSortDirection::Asc => "↑", PacketSortDirection::Desc => "↓" }
            } else { "" }),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("5.Destination{}", if app.packet_sort_column == PacketSortColumn::DestIp {
                match app.packet_sort_direction { PacketSortDirection::Asc => "↑", PacketSortDirection::Desc => "↓" }
            } else { "" }),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
        Cell::from(Span::styled(
            format!("6.Size{}", if app.packet_sort_column == PacketSortColumn::Size {
                match app.packet_sort_direction { PacketSortDirection::Asc => "↑", PacketSortDirection::Desc => "↓" }
            } else { "" }),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        )),
    ]);

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
        format!("Packets - Showing {}-{} of {}", visible_start, visible_end, filtered_count)
    };

    let table = Table::new(
        rows,
        &[
            Constraint::Length(15),  // Time (with milliseconds)
            Constraint::Length(6),   // Dir
            Constraint::Length(8),   // Proto
            Constraint::Percentage(30), // Src
            Constraint::Percentage(30), // Dst
            Constraint::Min(10),     // Size
        ],
    )
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