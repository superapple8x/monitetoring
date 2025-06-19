use crate::types::{App, PacketCacheMeta, PacketSortColumn, PacketSortDirection};

/// Ensure that `app.packet_cache` contains indices of packets that satisfy the
/// current filter & sort settings. Rebuilds the vector only when something has
/// changed (filter, sort, history length, or selected PID).
pub fn ensure_packet_cache(app: &mut App, pid: i32) {
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
    } else {
        false
    };

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
                if p.protocol != proto {
                    return false;
                }
            }
            if let Some(dir) = filter.direction {
                if p.direction != dir {
                    return false;
                }
            }
            if let Some(re) = &filter.search_regex {
                let search_text = format!(
                    "{}:{} {}:{}",
                    p.src_ip, p.src_port, p.dst_ip, p.dst_port
                );
                if !re.is_match(&search_text) {
                    return false;
                }
            } else if let Some(term) = &filter.search_term {
                let search_text = format!(
                    "{}:{} {}:{}",
                    p.src_ip,
                    p.src_port,
                    p.dst_ip,
                    p.dst_port
                )
                .to_lowercase();
                if !search_text.contains(term) {
                    return false;
                }
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
pub fn filters_equal(
    a: &Option<crate::types::PacketFilter>,
    b: &Option<crate::types::PacketFilter>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(fa), Some(fb)) => {
            fa.protocol == fb.protocol
                && fa.direction == fb.direction
                && fa.search_term == fb.search_term
                && match (&fa.search_regex, &fb.search_regex) {
                    (None, None) => true,
                    (Some(ra), Some(rb)) => ra.as_str() == rb.as_str(),
                    _ => false,
                }
        }
        _ => false,
    }
} 