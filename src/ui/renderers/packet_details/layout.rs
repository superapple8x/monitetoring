use ratatui::{
    layout::Constraint,
    style::{Style, Modifier, Color},
    text::Span,
    widgets::{Cell, Row},
};

use crate::types::{App, PacketDirection, PacketSortColumn};
use crate::config;
use super::cache::ConnKey;

use super::utils::*;

/// Build table data (rows, header, constraints) based on terminal width
pub fn build_responsive_table_data<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
    terminal_width: u16,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    let (large_packet_threshold, frequent_connection_threshold) =
        if let Some(config) = config::load_config() {
            (
                config.large_packet_threshold,
                config.frequent_connection_threshold,
            )
        } else {
            // Fallback to defaults if config fails to load
            (100_000, 20)
        };

    if terminal_width < NARROW_TERMINAL_THRESHOLD {
        build_narrow_layout(
            app,
            process_info,
            scroll_offset,
            end_idx,
            large_packet_threshold,
            frequent_connection_threshold,
        )
    } else if terminal_width < WIDE_TERMINAL_THRESHOLD {
        build_medium_layout(
            app,
            process_info,
            scroll_offset,
            end_idx,
            large_packet_threshold,
            frequent_connection_threshold,
        )
    } else {
        build_wide_layout(
            app,
            process_info,
            scroll_offset,
            end_idx,
            large_packet_threshold,
            frequent_connection_threshold,
        )
    }
}

// ============================================================
// Narrow terminal layout (< 80 chars)
// ============================================================

fn build_narrow_layout<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
    large_packet_threshold: usize,
    frequent_connection_threshold: usize,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    // Get base timestamp for relative timing (first packet in current view)
    let base_time = if !process_info.packet_history.is_empty() {
        Some(process_info.packet_history[0].timestamp)
    } else {
        None
    };

    // Build frequency map for connection counts within the visible slice
    let slice = &app.packet_cache[scroll_offset..end_idx];
    let mut conn_counts: std::collections::HashMap<ConnKey, usize> = std::collections::HashMap::new();
    for &packet_idx in slice {
        let p = &process_info.packet_history[packet_idx];
        let key = ConnKey::from_packet(p);
        *conn_counts.entry(key).or_insert(0) += 1;
    }

    let mut rows: Vec<Row> = Vec::with_capacity(slice.len());

    for (i, &packet_idx) in slice.iter().enumerate() {
        let p = &process_info.packet_history[packet_idx];
        let conn_key = ConnKey::from_packet(p);

        // Get pre-computed row style from the render cache
        let row_style = app.packet_render_cache[scroll_offset + i].row_style;

        // Timestamp (relative)
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
        let frequent = conn_counts.get(&conn_key).copied().unwrap_or(0) > frequent_connection_threshold;
        let connection_cell = if frequent {
            Cell::from(Span::styled(connection_summary, Style::default().fg(Color::LightCyan)))
        } else {
            Cell::from(connection_summary)
        };

        // Size cell highlight
        let size_cell = if p.size > large_packet_threshold {
            Cell::from(Span::styled(p.cached_size.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
        } else {
            Cell::from(p.cached_size.clone())
        };

        let row = Row::new(vec![
            Cell::from(timestamp),
            proto_cell,
            connection_cell,
            size_cell,
        ])
        .style(row_style);
        rows.push(row);
    }

    // Compact headers for narrow terminals
    let header = Row::new(vec![
        Cell::from(Span::styled(
            format!("1.Time{}", get_sort_indicator(app, PacketSortColumn::Timestamp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("2.P/D{}", get_combined_sort_indicator(app, PacketSortColumn::Protocol, PacketSortColumn::Direction)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("3.Connection{}", get_combined_sort_indicator(app, PacketSortColumn::SourceIp, PacketSortColumn::DestIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("4.Size{}", get_sort_indicator(app, PacketSortColumn::Size)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
    ]);

    let constraints = vec![
        Constraint::Length(8),  // Time (HH:MM:SS)
        Constraint::Length(6),  // Proto+Dir
        Constraint::Min(20),    // Connection
        Constraint::Length(8),  // Size
    ];

    (rows, header, constraints)
}

// ============================================================
// Medium terminal layout (80-120 chars)
// ============================================================

fn build_medium_layout<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
    large_packet_threshold: usize,
    frequent_connection_threshold: usize,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    let slice = &app.packet_cache[scroll_offset..end_idx];
    let mut conn_counts: std::collections::HashMap<ConnKey, usize> = std::collections::HashMap::new();
    for &packet_idx in slice {
        let pkt = &process_info.packet_history[packet_idx];
        let key = ConnKey::from_packet(pkt);
        *conn_counts.entry(key).or_insert(0) += 1;
    }

    let mut rows: Vec<Row> = Vec::with_capacity(slice.len());

    for (i, &packet_idx) in slice.iter().enumerate() {
        let p = &process_info.packet_history[packet_idx];
        let conn_key = ConnKey::from_packet(p);

        let row_style = app.packet_render_cache[scroll_offset + i].row_style;

        let timestamp = if p.cached_ts.len() > 12 {
            &p.cached_ts[..12]
        } else {
            &p.cached_ts
        };
        let dir_str = match p.direction {
            PacketDirection::Sent => "↑",
            PacketDirection::Received => "↓",
        };
        let proto_color = get_protocol_color(&p.cached_proto);
        let proto_cell = Cell::from(Span::styled(p.cached_proto.clone(), Style::default().fg(proto_color).add_modifier(Modifier::BOLD)));

        let enhanced_src = format_endpoint_smart(
            &p.src_ip.to_string(),
            p.src_port,
            p.src_ip.to_string().starts_with("127.0.0.1") || p.src_ip.to_string().starts_with("::1"),
        );
        let enhanced_dst = format_endpoint_smart(
            &p.dst_ip.to_string(),
            p.dst_port,
            p.dst_ip.to_string().starts_with("127.0.0.1") || p.dst_ip.to_string().starts_with("::1"),
        );
        let frequent = conn_counts.get(&conn_key).copied().unwrap_or(0) > frequent_connection_threshold;
        let src_cell = if frequent {
            Cell::from(Span::styled(enhanced_src, Style::default().fg(Color::LightCyan)))
        } else {
            Cell::from(enhanced_src)
        };
        let dst_cell = if frequent {
            Cell::from(Span::styled(enhanced_dst, Style::default().fg(Color::LightCyan)))
        } else {
            Cell::from(enhanced_dst)
        };

        let size_cell = if p.size > large_packet_threshold {
            Cell::from(Span::styled(p.cached_size.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
        } else {
            Cell::from(p.cached_size.clone())
        };

        rows.push(Row::new(vec![
            Cell::from(timestamp.to_string()),
            Cell::from(dir_str.to_string()),
            proto_cell,
            src_cell,
            dst_cell,
            size_cell,
        ])
        .style(row_style));
    }

    let header = Row::new(vec![
        Cell::from(Span::styled(
            format!("1.Time{}", get_sort_indicator(app, PacketSortColumn::Timestamp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("2.Dir{}", get_sort_indicator(app, PacketSortColumn::Direction)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("3.Proto{}", get_sort_indicator(app, PacketSortColumn::Protocol)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("4.Source{}", get_sort_indicator(app, PacketSortColumn::SourceIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("5.Dest{}", get_sort_indicator(app, PacketSortColumn::DestIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("6.Size{}", get_sort_indicator(app, PacketSortColumn::Size)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
    ]);

    let constraints = vec![
        Constraint::Length(12),  // Time
        Constraint::Length(5),   // Dir
        Constraint::Length(6),   // Proto
        Constraint::Percentage(28), // Source
        Constraint::Percentage(28), // Dest
        Constraint::Length(10),  // Size
    ];

    (rows, header, constraints)
}

// ============================================================
// Wide terminal layout (>= 120 chars)
// ============================================================

fn build_wide_layout<'a>(
    app: &'a App,
    process_info: &'a crate::types::ProcessInfo,
    scroll_offset: usize,
    end_idx: usize,
    large_packet_threshold: usize,
    frequent_connection_threshold: usize,
) -> (Vec<Row<'a>>, Row<'a>, Vec<Constraint>) {
    let slice = &app.packet_cache[scroll_offset..end_idx];
    let mut conn_counts: std::collections::HashMap<ConnKey, usize> = std::collections::HashMap::new();
    for &idx in slice {
        let p = &process_info.packet_history[idx];
        let key = ConnKey::from_packet(p);
        *conn_counts.entry(key).or_insert(0) += 1;
    }

    let mut rows: Vec<Row> = Vec::with_capacity(slice.len());

    for (i, &packet_idx) in slice.iter().enumerate() {
        let p = &process_info.packet_history[packet_idx];
        let conn_key = ConnKey::from_packet(p);

        let mut style = app.packet_render_cache[scroll_offset + i].row_style;
        style = match p.direction {
            PacketDirection::Sent => style.fg(Color::LightBlue),
            PacketDirection::Received => style.fg(Color::LightGreen),
        };

        let timestamp = p.cached_ts.as_str();
        let dir_str = match p.direction {
            PacketDirection::Sent => "↑ OUT",
            PacketDirection::Received => "↓ IN",
        };
        let proto_color = get_protocol_color(&p.cached_proto);

        let enhanced_src = format_endpoint_smart(
            &p.src_ip.to_string(),
            p.src_port,
            p.src_ip.to_string().starts_with("127.0.0.1") || p.src_ip.to_string().starts_with("::1"),
        );
        let enhanced_dst = format_endpoint_smart(
            &p.dst_ip.to_string(),
            p.dst_port,
            p.dst_ip.to_string().starts_with("127.0.0.1") || p.dst_ip.to_string().starts_with("::1"),
        );

        let frequent = conn_counts.get(&conn_key).copied().unwrap_or(0) > frequent_connection_threshold;
        let src_cell = if frequent {
            Cell::from(Span::styled(enhanced_src, Style::default().fg(Color::LightCyan)))
        } else {
            Cell::from(enhanced_src)
        };
        let dst_cell = if frequent {
            Cell::from(Span::styled(enhanced_dst, Style::default().fg(Color::LightCyan)))
        } else {
            Cell::from(enhanced_dst)
        };

        let size_cell = if p.size > large_packet_threshold {
            Cell::from(Span::styled(p.cached_size.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
        } else {
            Cell::from(p.cached_size.clone())
        };

        rows.push(Row::new(vec![
            Cell::from(timestamp),
            Cell::from(Span::styled(dir_str.to_string(), Style::default().add_modifier(Modifier::BOLD))),
            Cell::from(Span::styled(p.cached_proto.clone(), Style::default().fg(proto_color).add_modifier(Modifier::BOLD))),
            src_cell,
            dst_cell,
            size_cell,
        ])
        .style(style));
    }

    let header = Row::new(vec![
        Cell::from(Span::styled(
            format!("1.Timestamp{}", get_sort_indicator(app, PacketSortColumn::Timestamp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("2.Direction{}", get_sort_indicator(app, PacketSortColumn::Direction)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("3.Protocol{}", get_sort_indicator(app, PacketSortColumn::Protocol)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("4.Source{}", get_sort_indicator(app, PacketSortColumn::SourceIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("5.Destination{}", get_sort_indicator(app, PacketSortColumn::DestIp)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
        Cell::from(Span::styled(
            format!("6.Size{}", get_sort_indicator(app, PacketSortColumn::Size)),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        )),
    ]);

    let constraints = vec![
        Constraint::Length(15), // Full timestamp
        Constraint::Length(7),  // Direction
        Constraint::Length(8),  // Protocol
        Constraint::Percentage(27), // Source
        Constraint::Percentage(27), // Destination
        Constraint::Length(12), // Size
    ];

    (rows, header, constraints)
} 