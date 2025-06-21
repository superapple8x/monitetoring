use ratatui::{Frame, layout::{Constraint, Direction, Layout}, widgets::{Block, Borders, Paragraph, Table, Wrap}, style::{Style, Color}, text::{Span, Line}};

use crate::types::{App, PacketDirection, PacketSortColumn, PacketSortDirection};

use super::{cache::ensure_packet_cache, layout::build_responsive_table_data, utils::*};

/// Render per-packet details for the selected process
pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.size();
    let terminal_width = area.width;

    // Dynamically calculate export footer height so long paths are not truncated
    let base_footer_height: u16 = 4; // minimum height (matches previous fixed size)
    let export_footer_height: u16 = match &app.export_notification_state {
        crate::types::NotificationState::Active(msg) => {
            // Rough estimate of wrapped line count (leave 4 chars for borders/padding)
            let usable_width = terminal_width.saturating_sub(4) as usize;
            if usable_width == 0 {
                base_footer_height
            } else {
                let lines_needed = (msg.len() + usable_width - 1) / usable_width; // ceil division
                (lines_needed as u16 + 2).max(base_footer_height) // +2 for block borders
            }
        }
        _ => base_footer_height,
    };

    // Fixed footer approach with dynamic height to avoid layout jumps while showing full path
    let chunks = if app.packet_search_mode {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Status/help line
                Constraint::Length(3), // Search input bar
                Constraint::Min(0),    // Main table
                Constraint::Length(export_footer_height), // Export notification (dynamic)
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Status/help line
                Constraint::Min(0),    // Main table
                Constraint::Length(export_footer_height), // Export notification (dynamic)
            ])
            .split(area)
    };

    let mut chunk_idx = 0;

    // If no process is selected, display guidance message
    let pid = match app.selected_process {
        Some(pid) => pid,
        None => {
            let help_text = Paragraph::new(
                "No process selected. Go back to main view and select a process to see packet details.",
            )
            .block(Block::default().title("Packet Details").borders(Borders::ALL))
            .style(Style::default().fg(Color::Yellow));
            f.render_widget(help_text, area);
            return;
        }
    };

    // Keep cache fresh before we immutably borrow process info
    ensure_packet_cache(app, pid);

    let process_info = app.stats.get(&pid).expect("process should exist");

    let total_packets = process_info.packet_history.len();
    let filtered_count = app.packet_cache.len();

    // --------------------------------
    // STATUS LINE (filters, controls)
    // --------------------------------

    let filter_info = if let Some(filter) = &app.packet_filter {
        let mut parts: Vec<String> = Vec::new();
        if let Some(proto) = filter.protocol {
            parts.push(match proto {
                6 => "TCP".into(),
                17 => "UDP".into(),
                1 => "ICMP".into(),
                other => format!("Proto {}", other),
            });
        }
        if let Some(dir) = filter.direction {
            parts.push(match dir {
                PacketDirection::Sent => "Sent".into(),
                PacketDirection::Received => "Received".into(),
            });
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

    let header_title = format!("Packet Details - {} (PID {})", process_info.name, pid);

    let status_text = if filtered_count == 0 {
        if total_packets == 0 {
            "Network activity will appear here in real-time.".to_string()
        } else {
            format!("{}No packets match current filter", filter_info)
        }
    } else {
        if terminal_width < NARROW_TERMINAL_THRESHOLD {
            format!("{}{}↑↓:scroll /:search e:export Esc:back", filter_info, sort_info)
        } else {
            format!("{}{}Controls: ↑↓:scroll PgUp/PgDn:page 1-6:sort /:search e:export Esc:back", filter_info, sort_info)
        }
    };

    let status = Paragraph::new(Line::from(vec![Span::styled(
        status_text,
        Style::default().fg(if filtered_count == 0 {
            Color::Yellow
        } else {
            Color::Cyan
        }),
    )]))
    .block(Block::default().title(header_title).borders(Borders::ALL));

    f.render_widget(status, chunks[chunk_idx]);
    chunk_idx += 1;

    // Render search input if enabled
    if app.packet_search_mode {
        let search_text = format!("Search: {}", app.packet_search_input);
        let search_bar = Paragraph::new(search_text)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Search (Enter: apply, Esc: cancel)"));
        f.render_widget(search_bar, chunks[chunk_idx]);
        chunk_idx += 1;
    }

    // No packets? stop early.
    if filtered_count == 0 {
        return;
    }

    let scroll_offset = app.packet_scroll_offset.min(filtered_count.saturating_sub(1));
    let visible_height = chunks[chunk_idx].height.saturating_sub(2) as usize; // minus borders & header
    app.packet_visible_rows = visible_height; // for PageUp/PageDown

    let end_idx = (scroll_offset + visible_height).min(filtered_count);

    // Build table rows + header via layout helper
    let (rows, header, constraints) = build_responsive_table_data(
        app,
        process_info,
        scroll_offset,
        end_idx,
        terminal_width,
    );

    // Table title with packet count info
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
            format!("Packets {}-{}/{}", visible_start, visible_end, filtered_count)
        } else {
            format!("Packets - Showing {}-{} of {}", visible_start, visible_end, filtered_count)
        }
    };

    let table = Table::new(rows, &constraints)
        .header(header)
        .block(Block::default().title(table_title).borders(Borders::ALL));

    f.render_widget(table, chunks[chunk_idx]);

    // --------------------------------
    //  Export notification footer
    // --------------------------------

    let export_notification_index = if app.packet_search_mode { 3 } else { 2 };

    match &app.export_notification_state {
        crate::types::NotificationState::Active(export_msg) => {
            let export_notification = Paragraph::new(export_msg.clone())
                .style(Style::default().fg(Color::Green))
                .wrap(Wrap { trim: true })
                .block(Block::default().title("Export Status").borders(Borders::ALL).border_style(Style::default().fg(Color::Green)));
            f.render_widget(export_notification, chunks[export_notification_index]);
        }
        crate::types::NotificationState::Expiring => {
            let fading_notification = Paragraph::new("Notification clearing...")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::NONE));
            f.render_widget(fading_notification, chunks[export_notification_index]);
        }
        crate::types::NotificationState::None => {
            let empty_footer = Paragraph::new("").block(Block::default().borders(Borders::NONE));
            f.render_widget(empty_footer, chunks[export_notification_index]);
        }
    }
} 