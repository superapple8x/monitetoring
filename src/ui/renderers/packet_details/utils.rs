use ratatui::style::{Color};
use crate::types::{App, PacketSortColumn, PacketSortDirection, PacketDirection};

// =====================
// Size / width constants
// =====================

/// Terminal width thresholds for responsive layout
pub const NARROW_TERMINAL_THRESHOLD: u16 = 80;
pub const WIDE_TERMINAL_THRESHOLD: u16 = 120;

// =====================
// Port helpers
// =====================

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
pub fn format_port_with_service(port: u16) -> String {
    if let Some(service) = get_port_name(port) {
        format!("{}({})", port, service)
    } else {
        port.to_string()
    }
}

// =====================
// Colour helpers
// =====================

/// Get protocol colour for better visual distinction
pub fn get_protocol_color(protocol: &str) -> Color {
    match protocol {
        "TCP" => Color::Red,
        "UDP" => Color::Green,
        "ICMP" => Color::Yellow,
        _ => Color::White,
    }
}

// =====================
// Endpoint helpers
// =====================

/// Truncate IP address for space efficiency
pub fn truncate_ip(ip: &str, max_len: usize) -> String {
    if ip.len() <= max_len {
        ip.to_string()
    } else {
        format!("{}…", &ip[..max_len.saturating_sub(1)])
    }
}

/// Smart endpoint formatting - prioritises external/interesting end-points
pub fn format_endpoint_smart(ip: &str, port: u16, is_localhost: bool) -> String {
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

/// Format connection with directional arrow and smart endpoint prioritisation
pub fn format_connection_enhanced(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    direction: PacketDirection,
) -> String {
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

// =====================
// Timestamp helpers
// =====================

/// Calculate relative timestamp from the first packet in the list
pub fn format_relative_timestamp(
    current_time: std::time::SystemTime,
    base_time: Option<std::time::SystemTime>,
    use_relative: bool,
) -> String {
    if !use_relative {
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
            let dt: chrono::DateTime<chrono::Local> = current_time.into();
            dt.format("%H:%M:%S%.3f").to_string()
        }
    } else {
        let dt: chrono::DateTime<chrono::Local> = current_time.into();
        dt.format("%H:%M:%S%.3f").to_string()
    }
}

// =====================
// Sorting helpers (just indicator rendering)
// =====================

/// Helper function to get sort indicator for a column
pub fn get_sort_indicator(app: &App, column: PacketSortColumn) -> String {
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
pub fn get_combined_sort_indicator(
    app: &App,
    col1: PacketSortColumn,
    col2: PacketSortColumn,
) -> String {
    if app.packet_sort_column == col1 || app.packet_sort_column == col2 {
        match app.packet_sort_direction {
            PacketSortDirection::Asc => "↑".to_string(),
            PacketSortDirection::Desc => "↓".to_string(),
        }
    } else {
        String::new()
    }
} 