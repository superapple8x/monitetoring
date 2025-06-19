use ratatui::{Frame, layout::{Constraint, Direction, Layout}, widgets::{Block, Borders, Row, Table, Cell, Paragraph}, style::{Style, Modifier, Color}, text::{Span, Line}};
use crate::types::{App, PacketDirection, PacketSortColumn, PacketSortDirection, PacketInfo};

/// Render per-packet details for the selected process
pub fn render(f: &mut Frame, app: &App) {
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

    let process_info = match app.stats.get(&pid) {
        Some(info) => info,
        None => {
            let help_text = Paragraph::new("Process not found or no longer active.")
                .block(Block::default().title("Packet Details").borders(Borders::ALL))
                .style(Style::default().fg(Color::Red));
            f.render_widget(help_text, area);
            return;
        }
    };

    // Apply filtering and collect into Vec for sorting
    let mut packets: Vec<&PacketInfo> = process_info.packet_history.iter().filter(|p| {
        if let Some(filter) = &app.packet_filter {
            if let Some(proto) = filter.protocol {
                if p.protocol != proto { return false; }
            }
            if let Some(dir) = filter.direction {
                if p.direction != dir { return false; }
            }
            if let Some(search_term) = &filter.search_term {
                let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port).to_lowercase();
                if !search_text.contains(search_term) { return false; }
            }
        }
        true
    }).collect();

    let total_packets = process_info.packet_history.len();
    let filtered_count = packets.len();

    // Apply sorting
    packets.sort_by(|a, b| {
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

    // Render status line with filtering info and navigation hints
    let filter_info = if let Some(filter) = &app.packet_filter {
        let mut parts = Vec::new();
        
        if let Some(proto) = filter.protocol {
            let proto_str = match proto {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMP",
                other => {
                    let owned = format!("Proto {}", other);
                    Box::leak(owned.into_boxed_str())
                }
            };
            parts.push(proto_str);
        }
        
        if let Some(dir) = filter.direction {
            let dir_str = match dir {
                PacketDirection::Sent => "Sent",
                PacketDirection::Received => "Received",
            };
            parts.push(dir_str);
        }
        
        if let Some(search) = &filter.search_term {
            let search_formatted = format!("\"{}\"", search);
            parts.push(Box::leak(search_formatted.into_boxed_str()));
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
        format!("{}{}Controls: ↑↓:scroll 1-6:sort /:search e:export Esc:back", 
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

    let scroll_offset = app.packet_scroll_offset.min(packets.len());
    let visible_height = chunks[chunk_idx].height.saturating_sub(2) as usize; // minus borders & header
    let slice_end = scroll_offset + visible_height;
    let slice = &packets[scroll_offset..packets.len().min(slice_end)];

    // Build rows with enhanced styling
    let rows: Vec<Row> = slice.iter().enumerate().map(|(i, p)| {
        let ts: chrono::DateTime<chrono::Local> = p.timestamp.into();
        let ts_str = ts.format("%H:%M:%S%.3f").to_string(); // Include milliseconds
        let dir_str = match p.direction {
            PacketDirection::Sent => "↑",  // Up arrow for sent
            PacketDirection::Received => "↓",  // Down arrow for received
        };
        let proto_str = match p.protocol {
            6 => "TCP",
            17 => "UDP", 
            1 => "ICMP",
            other => {
                Box::leak(format!("{}", other).into_boxed_str())
            }
        };

        // Alternate row colors for better readability
        let style = if i % 2 == 0 {
            Style::default()
        } else {
            Style::default().bg(Color::DarkGray)
        };

        Row::new(vec![
            ts_str,
            dir_str.to_string(),
            proto_str.to_string(),
            format!("{}:{}", p.src_ip, p.src_port),
            format!("{}:{}", p.dst_ip, p.dst_port),
            format!("{}", crate::ui::utils::format_bytes(p.size as u64)),
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
            if let Some(search_term) = &filter.search_term {
                let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port).to_lowercase();
                if !search_text.contains(search_term) { return false; }
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
        let protocol = match packet.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            other => {
                Box::leak(format!("{}", other).into_boxed_str())
            }
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