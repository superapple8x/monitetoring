use crate::types::{App, PacketDirection};

/// Export packets to CSV file
pub fn export_packets_to_csv(
    app: &mut App,
    process_info: &crate::types::ProcessInfo,
    _pid: i32,
) -> Result<(), Box<dyn std::error::Error>> {
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
    writeln!(
        file,
        "Timestamp,Direction,Protocol,Source_IP,Source_Port,Dest_IP,Dest_Port,Size_Bytes"
    )?;

    // Apply same filtering logic as the UI
    let filtered_packets: Vec<_> = process_info
        .packet_history
        .iter()
        .filter(|p| {
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
                    let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                    if !re.is_match(&search_text) {
                        return false;
                    }
                } else if let Some(term) = &filter.search_term {
                    let search_text = format!("{}:{} {}:{}", p.src_ip, p.src_port, p.dst_ip, p.dst_port)
                        .to_lowercase();
                    if !search_text.contains(term) {
                        return false;
                    }
                }
            }
            true
        })
        .collect();

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
    let export_msg = format!(
        "✓ Successfully exported {} packets to file '{}' in {}",
        packet_count, filename, current_dir
    );

    app.export_notification_state = crate::types::NotificationState::Active(export_msg);
    app.export_notification_time = Some(Instant::now());

    Ok(())
} 