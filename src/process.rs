use std::collections::HashMap;
use crate::types::{Connection, ProcessIdentifier};

pub fn extract_container_name(pid: i32) -> Option<String> {
    // Read /proc/[PID]/cgroup to extract container information
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    
    if let Ok(cgroup_content) = std::fs::read_to_string(&cgroup_path) {
        for line in cgroup_content.lines() {
            // Look for Docker containers (typically in the format: 0::/docker/container_id)
            if line.contains("/docker/") {
                if let Some(docker_part) = line.split("/docker/").nth(1) {
                    let container_id = docker_part.trim();
                    if container_id.len() >= 12 {
                        return Some(format!("docker:{}", &container_id[..12]));
                    }
                }
            }
            // Look for systemd Docker containers (format: 0::/system.slice/docker-container_id.scope)
            else if line.contains("/system.slice/docker-") && line.contains(".scope") {
                if let Some(docker_part) = line.split("/system.slice/docker-").nth(1) {
                    if let Some(container_id) = docker_part.split(".scope").next() {
                        if container_id.len() >= 12 {
                            return Some(format!("docker:{}", &container_id[..12]));
                        }
                    }
                }
            }
            // Look for Podman containers (typically in the format: 0::/machine.slice/libpod-container_id.scope)
            else if line.contains("/libpod-") && line.contains(".scope") {
                if let Some(podman_part) = line.split("/libpod-").nth(1) {
                    if let Some(container_id) = podman_part.split(".scope").next() {
                        if container_id.len() >= 12 {
                            return Some(format!("podman:{}", &container_id[..12]));
                        }
                    }
                }
            }
            // Look for containerd containers (typically in the format: 0::/system.slice/containerd.service)
            else if line.contains("/containerd") {
                return Some("containerd".to_string());
            }
            // Look for systemd-nspawn containers
            else if line.contains("/machine.slice/systemd-nspawn") {
                if let Some(nspawn_part) = line.split("/systemd-nspawn@").nth(1) {
                    if let Some(container_name) = nspawn_part.split(".service").next() {
                        return Some(format!("nspawn:{}", container_name));
                    }
                }
            }
            // Look for LXC containers
            else if line.contains("/lxc/") {
                if let Some(lxc_part) = line.split("/lxc/").nth(1) {
                    let container_name = lxc_part.split('/').next().unwrap_or(lxc_part);
                    return Some(format!("lxc:{}", container_name));
                }
            }
        }
    }
    None
}

pub fn extract_user_name(pid: i32) -> Option<String> {
    // Read /proc/[PID]/status to get UID information
    let status_path = format!("/proc/{}/status", pid);
    
    if let Ok(status_content) = std::fs::read_to_string(&status_path) {
        for line in status_content.lines() {
            if line.starts_with("Uid:") {
                // Uid line format: "Uid:	real	effective	saved	filesystem"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(uid) = parts[1].parse::<u32>() {
                        // Try to get username from UID
                        return get_username_from_uid(uid);
                    }
                }
                break;
            }
        }
    }
    None
}

fn get_username_from_uid(uid: u32) -> Option<String> {
    // Try to read /etc/passwd to map UID to username
    if let Ok(passwd_content) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd_content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(file_uid) = parts[2].parse::<u32>() {
                    if file_uid == uid {
                        return Some(parts[0].to_string());
                    }
                }
            }
        }
    }
    
    // Fallback: return UID as string if username lookup fails
    Some(uid.to_string())
}

pub fn refresh_proc_maps(containers_mode: bool) -> (HashMap<u64, ProcessIdentifier>, HashMap<Connection, u64>) {
    let mut inode_to_pid_map: HashMap<u64, ProcessIdentifier> = HashMap::new();
    let mut connection_to_inode_map: HashMap<Connection, u64> = HashMap::new();

    if let Ok(all_procs) = procfs::process::all_processes() {
        for proc in all_procs {
            if let Ok(p) = proc {
                let name = p.stat().map_or_else(|_| "???".to_string(), |s| s.comm);
                let container_name = if containers_mode {
                    extract_container_name(p.pid)
                } else {
                    None
                };
                let user_name = extract_user_name(p.pid);
                
                if let Ok(fds) = p.fd() {
                    for fd in fds {
                        if let Ok(fd_info) = fd {
                            if let procfs::process::FDTarget::Socket(inode) = fd_info.target {
                                inode_to_pid_map.insert(inode, ProcessIdentifier { 
                                    pid: p.pid, 
                                    name: name.clone(),
                                    container_name: container_name.clone(),
                                    user_name: user_name.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // TCP connections
    if let Ok(tcp) = procfs::net::tcp() {
        for entry in tcp {
            let conn = Connection {
                source_ip: entry.local_address.ip(),
                dest_ip: entry.remote_address.ip(),
                source_port: entry.local_address.port(),
                dest_port: entry.remote_address.port(),
                protocol: 6, // TCP
            };
            connection_to_inode_map.insert(conn, entry.inode);
        }
    }

    // UDP connections
    if let Ok(udp) = procfs::net::udp() {
        for entry in udp {
            let conn = Connection {
                source_ip: entry.local_address.ip(),
                dest_ip: entry.remote_address.ip(),
                source_port: entry.local_address.port(),
                dest_port: entry.remote_address.port(),
                protocol: 17, // UDP
            };
            connection_to_inode_map.insert(conn, entry.inode);
        }
    }
    
    // TCP6 connections
    if let Ok(tcp6) = procfs::net::tcp6() {
        for entry in tcp6 {
            let conn = Connection {
                source_ip: entry.local_address.ip(),
                dest_ip: entry.remote_address.ip(),
                source_port: entry.local_address.port(),
                dest_port: entry.remote_address.port(),
                protocol: 6, // TCP
            };
            connection_to_inode_map.insert(conn, entry.inode);
        }
    }

    // UDP6 connections
    if let Ok(udp6) = procfs::net::udp6() {
        for entry in udp6 {
            let conn = Connection {
                source_ip: entry.local_address.ip(),
                dest_ip: entry.remote_address.ip(),
                source_port: entry.local_address.port(),
                dest_port: entry.remote_address.port(),
                protocol: 17, // UDP
            };
            connection_to_inode_map.insert(conn, entry.inode);
        }
    }

    (inode_to_pid_map, connection_to_inode_map)
} 