use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::types::{Connection, ProcessIdentifier, ProcessInfo};

/// Check if Npcap or WinPcap is installed and available
pub fn check_packet_capture_available() -> Result<(), String> {
    // Check if npcap service is installed and running
    use std::process::Command;
    
    let output = Command::new("sc")
        .args(["query", "npcap"])
        .output();
    
    match output {
        Ok(result) => {
            let output_str = String::from_utf8_lossy(&result.stdout);
            if output_str.contains("RUNNING") || output_str.contains("STOPPED") {
                return Ok(()); // Npcap service exists (running or stopped is fine)
            }
        }
        Err(_) => {
            // If sc command fails, try checking for WinPcap as fallback
            let winpcap_output = Command::new("sc")
                .args(["query", "npf"])
                .output();
            
            if let Ok(result) = winpcap_output {
                let output_str = String::from_utf8_lossy(&result.stdout);
                if output_str.contains("RUNNING") || output_str.contains("STOPPED") {
                    return Ok(()); // WinPcap service exists
                }
            }
        }
    }
    
    Err(format!(
        "❌ Packet capture driver not found!\n\n\
        Monitetoring requires Npcap or WinPcap to capture network packets.\n\n\
        Please install Npcap from: https://npcap.com/\n\
        \n\
        After installation:\n\
        1. Reboot your computer (if prompted)\n\
        2. Run this tool as Administrator\n\
        \n\
        Note: Npcap is free and safe - it's the standard packet capture\n\
        library used by Wireshark and many other network tools."
    ))
}

// Synthetic inode counter for Windows (since Windows doesn't have socket inodes)
static SYNTHETIC_INODE: AtomicU64 = AtomicU64::new(1);

pub fn extract_container_name(_pid: i32) -> Option<String> {
    // Container awareness is not supported on Windows yet
    None
}

pub fn extract_user_name(_pid: i32) -> Option<String> {
    // Username extraction not implemented yet for Windows
    // Could be added later using Windows APIs or sysinfo
    None
}

pub fn refresh_proc_maps(_containers_mode: bool) -> (HashMap<u64, ProcessIdentifier>, HashMap<Connection, u64>) {
    let mut inode_to_pid_map: HashMap<u64, ProcessIdentifier> = HashMap::new();
    let mut connection_to_inode_map: HashMap<Connection, u64> = HashMap::new();

    // Use netstat2 to get socket information with associated PIDs
    let af_flags = netstat2::AddressFamilyFlags::IPV4 | netstat2::AddressFamilyFlags::IPV6;
    let proto_flags = netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP;
    
    if let Ok(sockets_info) = netstat2::get_sockets_info(af_flags, proto_flags) {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_processes();
        
        for socket_info in sockets_info {
            // Generate a synthetic inode for this socket
            let synthetic_inode = SYNTHETIC_INODE.fetch_add(1, Ordering::SeqCst);
            
            // Process each PID associated with this socket
            for &pid in &socket_info.associated_pids {
                let name = sys.process(sysinfo::Pid::from_u32(pid))
                    .map(|p| p.name().to_string())
                    .unwrap_or_else(|| "???".to_string());
                
                let process_identifier = ProcessIdentifier {
                    pid: pid as i32,
                    name,
                    container_name: None, // Windows doesn't support container detection yet
                    user_name: None,      // Windows user detection not implemented yet
                };
                
                inode_to_pid_map.insert(synthetic_inode, process_identifier);
            }
            
            // Create Connection from socket info
            let connection = match socket_info.protocol_socket_info {
                netstat2::ProtocolSocketInfo::Tcp(tcp_info) => Connection {
                    source_ip: tcp_info.local_addr,
                    dest_ip: tcp_info.remote_addr,
                    source_port: tcp_info.local_port,
                    dest_port: tcp_info.remote_port,
                    protocol: 6, // TCP
                },
                netstat2::ProtocolSocketInfo::Udp(udp_info) => Connection {
                    source_ip: udp_info.local_addr,
                    dest_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), // UDP doesn't have remote addr
                    source_port: udp_info.local_port,
                    dest_port: 0, // UDP doesn't have remote port
                    protocol: 17, // UDP
                },
            };
            
            connection_to_inode_map.insert(connection, synthetic_inode);
        }
    }

    (inode_to_pid_map, connection_to_inode_map)
}

/// Check if a process with the given PID is still alive
pub fn is_process_alive(pid: i32) -> bool {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();
    sys.process(sysinfo::Pid::from_u32(pid as u32)).is_some()
}

/// Clean up dead processes from the stats HashMap
/// Returns a vector of PIDs that were removed
pub fn cleanup_dead_processes(stats: &mut HashMap<i32, ProcessInfo>, killed_processes: &std::collections::HashSet<i32>) -> Vec<i32> {
    let mut removed_pids = Vec::new();
    
    // Collect PIDs to remove (processes that are dead and not in killed_processes)
    let pids_to_remove: Vec<i32> = stats.keys()
        .filter(|&pid| {
            // Don't remove processes that were intentionally killed by the tool
            if killed_processes.contains(pid) {
                return false;
            }
            // Remove if the process is no longer alive
            !is_process_alive(*pid)
        })
        .cloned()
        .collect();
    
    // Remove dead processes and track what was removed
    for pid in pids_to_remove {
        if stats.remove(&pid).is_some() {
            removed_pids.push(pid);
        }
    }
    
    removed_pids
}

/// Validate if a process should be tracked (alive and not in exclusion sets)
pub fn should_track_process(pid: i32, killed_processes: &std::collections::HashSet<i32>, dead_processes_cache: &std::collections::HashSet<i32>) -> bool {
    // Don't track killed processes
    if killed_processes.contains(&pid) {
        return false;
    }
    
    // Don't track processes we know are dead
    if dead_processes_cache.contains(&pid) {
        return false;
    }
    
    // Final check: is the process actually alive?
    is_process_alive(pid)
} 