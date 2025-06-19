use ratatui::{Frame, layout::{Constraint, Direction, Layout}, widgets::{Block, Borders, Row, Table, Cell, Paragraph}, style::{Style, Modifier, Color}, text::{Span, Line}};
use crate::types::{App, PacketDirection};

/// Render per-packet details for the selected process
pub fn render(f: &mut Frame, app: &App) {
    let area = f.size();

    // Split area for status line and table
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Status/help line
            Constraint::Min(0),    // Main table
        ])
        .split(area);

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

    // Apply filtering (protocol, direction) if present
    let filtered_iter = process_info.packet_history.iter().rev().filter(|p| {
        if let Some(filter) = &app.packet_filter {
            if let Some(proto) = filter.protocol {
                if p.protocol != proto { return false; }
            }
            if let Some(dir) = filter.direction {
                if p.direction != dir { return false; }
            }
        }
        true
    });

    // Convert to Vec to support slicing/scrolling
    let packets: Vec<_> = filtered_iter.collect();
    let total_packets = process_info.packet_history.len();
    let filtered_count = packets.len();

    // Render status line with filtering info and navigation hints
    let filter_info = if let Some(filter) = &app.packet_filter {
        let proto_str = if let Some(proto) = filter.protocol {
            match proto {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                1 => "ICMP".to_string(),
                other => format!("Proto {}", other),
            }
        } else {
            "All".to_string()
        };
        
        let dir_str = if let Some(dir) = filter.direction {
            match dir {
                PacketDirection::Sent => "Sent",
                PacketDirection::Received => "Received",
            }
        } else {
            "Both"
        };
        
        format!("Filter: {} {} | ", proto_str, dir_str)
    } else {
        String::new()
    };

    let status_text = if filtered_count == 0 {
        if total_packets == 0 {
            "No packets captured yet. Network activity will appear here in real-time.".to_string()
        } else {
            format!("No packets match current filter. {}Total: {} packets", filter_info, total_packets)
        }
    } else {
        let visible_start = app.packet_scroll_offset + 1;
        let visible_end = (app.packet_scroll_offset + (chunks[1].height.saturating_sub(3) as usize)).min(filtered_count);
        format!("{}Showing {}-{} of {} packets | ↑↓:scroll Esc:back t:proto u:UDP i:ICMP r:dir s:sent c:clear", 
                filter_info, visible_start, visible_end, filtered_count)
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(status_text, Style::default().fg(if filtered_count == 0 { Color::Yellow } else { Color::Cyan }))
    ]))
    .block(Block::default().title(format!("Packet Details - {} (PID {})", 
        process_info.name, pid)).borders(Borders::ALL));
    
    f.render_widget(status, chunks[0]);

    // If no packets to show, we're done
    if filtered_count == 0 {
        return;
    }

    let scroll_offset = app.packet_scroll_offset.min(packets.len());
    let visible_height = chunks[1].height.saturating_sub(2) as usize; // minus borders & header
    let slice_end = scroll_offset + visible_height;
    let slice = &packets[scroll_offset..packets.len().min(slice_end)];

    // Build rows with enhanced styling
    let rows: Vec<Row> = slice.iter().enumerate().map(|(i, p)| {
        let ts: chrono::DateTime<chrono::Local> = (*p).timestamp.into();
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

    let header = Row::new(vec![
        Cell::from(Span::styled("Time", Style::default().add_modifier(Modifier::BOLD).fg(Color::Green))),
        Cell::from(Span::styled("Dir", Style::default().add_modifier(Modifier::BOLD).fg(Color::Green))),
        Cell::from(Span::styled("Proto", Style::default().add_modifier(Modifier::BOLD).fg(Color::Green))),
        Cell::from(Span::styled("Source", Style::default().add_modifier(Modifier::BOLD).fg(Color::Green))),
        Cell::from(Span::styled("Destination", Style::default().add_modifier(Modifier::BOLD).fg(Color::Green))),
        Cell::from(Span::styled("Size", Style::default().add_modifier(Modifier::BOLD).fg(Color::Green))),
    ]);

    let table = Table::new(
        rows,
        &[
            Constraint::Length(12),  // Time (with milliseconds)
            Constraint::Length(3),   // Dir
            Constraint::Length(6),   // Proto
            Constraint::Percentage(30), // Src
            Constraint::Percentage(30), // Dst
            Constraint::Min(8),      // Size
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(table, chunks[1]);
} 