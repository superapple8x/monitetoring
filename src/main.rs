use clap::Parser;
use pcap::{Device, Capture};
use serde::Serialize;
use std::process;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use tokio::sync::mpsc;
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Table, Row, Cell},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color},
    Terminal
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;
use std::thread;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    iface: Option<String>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    containers: bool,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
struct Connection {
    source_port: u16,
    dest_port: u16,
    source_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
    protocol: u8,
}

#[derive(Clone, Serialize)]
struct ProcessInfo {
    name: String,
    sent: u64,
    received: u64,
    container_name: Option<String>,
}

enum SortColumn {
    Pid,
    Name,
    Sent,
    Received,
    Container,
}

struct App {
    stats: HashMap<i32, ProcessInfo>,
    sort_by: SortColumn,
    containers_mode: bool,
}

impl App {
    fn new(containers_mode: bool) -> Self {
        App {
            stats: HashMap::new(),
            sort_by: SortColumn::Pid,
            containers_mode,
        }
    }

    fn sorted_stats(&self) -> Vec<(&i32, &ProcessInfo)> {
        let mut sorted: Vec<_> = self.stats.iter().collect();
        match self.sort_by {
            SortColumn::Pid => sorted.sort_by_key(|(pid, _)| *pid),
            SortColumn::Name => sorted.sort_by_key(|(_, info)| &info.name),
            SortColumn::Sent => {
                sorted.sort_by_key(|(_, info)| info.sent);
                sorted.reverse();
            }
            SortColumn::Received => {
                sorted.sort_by_key(|(_, info)| info.received);
                sorted.reverse();
            }
            SortColumn::Container => {
                sorted.sort_by_key(|(_, info)| &info.container_name);
            }
        }
        sorted
    }
}

#[derive(Clone)]
struct ProcessIdentifier {
    pid: i32,
    name: String,
    container_name: Option<String>,
}

fn extract_container_name(pid: i32) -> Option<String> {
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

fn refresh_proc_maps(containers_mode: bool) -> (HashMap<u64, ProcessIdentifier>, HashMap<Connection, u64>) {
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
                
                if let Ok(fds) = p.fd() {
                    for fd in fds {
                        if let Ok(fd_info) = fd {
                            if let procfs::process::FDTarget::Socket(inode) = fd_info.target {
                                inode_to_pid_map.insert(inode, ProcessIdentifier { 
                                    pid: p.pid, 
                                    name: name.clone(),
                                    container_name: container_name.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

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

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let cli = Cli::parse();

    if let Some(iface) = cli.iface {
        let (tx, mut rx) = mpsc::channel(100);

        // Spawn a regular thread for packet capture (not async)
        let iface_clone = iface.clone();
        let json_mode = cli.json;
        let containers_mode = cli.containers;
        thread::spawn(move || {
            let main_device = Device::from(iface_clone.as_str());
            
            let cap = match Capture::from_device(main_device) {
                Ok(cap) => cap,
                Err(e) => {
                    eprintln!("Error creating capture handle: {}", e);
                    process::exit(1);
                }
            };

            let cap = if iface_clone != "any" {
                cap.promisc(true)
            } else {
                cap
            };

            let mut cap = match cap.timeout(10).open() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error opening capture: {}", e);
                    process::exit(1);
                }
            };

            let mut bandwidth_map: HashMap<i32, ProcessInfo> = HashMap::new();
            let mut last_map_refresh = Instant::now();
            let mut last_send = Instant::now();
            let (mut inode_map, mut conn_map) = refresh_proc_maps(containers_mode);
            
            let capture_start = Instant::now();

            let mut packet_count = 0;

            loop {
                // In JSON mode, run for a limited time (e.g., 5 seconds) then exit thread
                if json_mode && capture_start.elapsed() > Duration::from_secs(5) {
                    let _ = tx.blocking_send(bandwidth_map.clone());
                    break;
                }

                // Refresh process maps every 2 seconds
                if last_map_refresh.elapsed() > Duration::from_secs(2) {
                    (inode_map, conn_map) = refresh_proc_maps(containers_mode);
                    last_map_refresh = Instant::now();
                }

                // Try to get a packet (with timeout)
                match cap.next_packet() {
                    Ok(packet) => {
                        packet_count += 1;
                        if packet_count % 100 == 1 {
                            // Debug: Packet count milestone
                        }
                        
                        if let Some(conn) = connection_from_packet(packet.data) {
                            if packet_count % 100 == 1 {
                                // Debug: Successfully parsed connection
                            }
                            
                            // Check both directions of the connection
                            let reverse_conn = Connection {
                                source_port: conn.dest_port,
                                dest_port: conn.source_port,
                                source_ip: conn.dest_ip,
                                dest_ip: conn.source_ip,
                                protocol: conn.protocol,
                            };
                            
                            let (matched_conn, found_inode) = if let Some(inode) = conn_map.get(&conn) {
                                (conn, *inode)
                            } else if let Some(inode) = conn_map.get(&reverse_conn) {
                                (reverse_conn, *inode)
                            } else {
                                if packet_count % 100 == 1 {
                                    // Debug: Connection not found in process maps
                                }
                                continue;
                            };
                            
                            if let Some(proc_identifier) = inode_map.get(&found_inode) {
                                let stats = bandwidth_map.entry(proc_identifier.pid).or_insert(ProcessInfo { 
                                    name: proc_identifier.name.clone(),
                                    sent: 0, 
                                    received: 0,
                                    container_name: proc_identifier.container_name.clone(),
                                });
                                
                                // Determine direction based on which connection matched
                                if matched_conn.source_ip == conn.source_ip {
                                    // Original direction
                                    if conn.source_ip.is_loopback() || conn.source_ip.is_multicast() {
                                        stats.sent += packet.data.len() as u64;
                                    } else {
                                        stats.received += packet.data.len() as u64;
                                    }
                                } else {
                                    // Reverse direction
                                    if conn.dest_ip.is_loopback() || conn.dest_ip.is_multicast() {
                                        stats.sent += packet.data.len() as u64;
                                    } else {
                                        stats.received += packet.data.len() as u64;
                                    }
                                }
                                
                                if packet_count % 100 == 1 {
                                    // Debug: Found matching process for connection
                                }
                            } else {
                                if packet_count % 100 == 1 {
                                    // Debug: Found inode but no PID mapping
                                }
                            }
                        } else {
                            // Debug: Failed to parse connection from packet
                        }
                    }
                    Err(_) => {
                        // Timeout or other error, continue
                    }
                }

                if !json_mode && last_send.elapsed() > Duration::from_secs(1) {
                    // Debug: Sending process entries to UI
                    let _ = tx.blocking_send(bandwidth_map.clone());
                    last_send = Instant::now();
                }
            }
        });

        if cli.json {
            // Display startup information for JSON mode
            eprintln!("🚀 Starting monitetoring...");
            eprintln!("📡 Interface: {}", iface);
            eprintln!("📊 Mode: JSON output");
            eprintln!("🐳 Container awareness: {}", if cli.containers { "Enabled" } else { "Disabled" });
            eprintln!("⏱️  Capturing for 5 seconds...");
            eprintln!();
            
            if let Some(final_stats) = rx.recv().await {
                if let Ok(json_output) = serde_json::to_string_pretty(&final_stats) {
                    println!("{}", json_output);
                }
            }
        } else {
            // Display startup information for TUI mode
            eprintln!("🚀 Starting monitetoring...");
            eprintln!("📡 Interface: {}", iface);
            eprintln!("📊 Mode: Interactive TUI");
            eprintln!("🐳 Container awareness: {}", if cli.containers { "Enabled" } else { "Disabled" });
            eprintln!("⏱️  Preparing to capture network traffic... (Press 'q' to quit)");
            eprintln!();
            eprintln!("🎯 Tip: Press 'p' for PID, 'n' for Name, 's' for Sent, 'r' for Received{}", 
                     if cli.containers { ", 'c' for Container" } else { "" });
            eprintln!("📊 Sorting: Higher bandwidth usage appears at the top");
            eprintln!();
            
            // Small delay to let user read the information
            std::thread::sleep(std::time::Duration::from_millis(2000));
            
            // This will be the UI task
            let mut app = App::new(cli.containers);
            let mut terminal = setup_terminal()?;
            
            loop {
                if let Ok(new_stats) = rx.try_recv() {
                    // Accumulate new data instead of replacing
                    for (pid, new_info) in new_stats {
                        let stats = app.stats.entry(pid).or_insert(ProcessInfo { name: new_info.name.clone(), sent: 0, received: 0, container_name: new_info.container_name.clone() });
                        stats.sent = new_info.sent;
                        stats.received = new_info.received;
                        stats.name = new_info.name;
                        stats.container_name = new_info.container_name;
                    }
                }
                
                terminal.draw(|f| {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .margin(1)
                        .constraints(
                            [
                                Constraint::Length(3), // Title
                                Constraint::Min(0),    // Table
                                Constraint::Length(3), // Footer
                            ]
                            .as_ref(),
                        )
                        .split(f.size());

                    let title = Block::default().title("Rust-Hogs").borders(Borders::ALL);
                    f.render_widget(title, chunks[0]);

                    let header_cells = if app.containers_mode {
                        vec!["(P)ID", "Name", "(S)ent", "(R)eceived", "(C)ontainer"]
                    } else {
                        vec!["(P)ID", "Name", "(S)ent", "(R)eceived"]
                    };
                    let header_cells: Vec<_> = header_cells
                        .iter()
                        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Red)))
                        .collect();
                    let header = Row::new(header_cells);

                    let rows = app.sorted_stats().into_iter().map(|(pid, data)| {
                        if app.containers_mode {
                            Row::new(vec![
                                Cell::from(pid.to_string()),
                                Cell::from(data.name.clone()),
                                Cell::from(data.sent.to_string()),
                                Cell::from(data.received.to_string()),
                                Cell::from(data.container_name.as_ref().unwrap_or(&"host".to_string()).clone()),
                            ])
                        } else {
                            Row::new(vec![
                                Cell::from(pid.to_string()),
                                Cell::from(data.name.clone()),
                                Cell::from(data.sent.to_string()),
                                Cell::from(data.received.to_string()),
                            ])
                        }
                    });

                    let widths = if app.containers_mode {
                        [
                            Constraint::Percentage(15),
                            Constraint::Percentage(25),
                            Constraint::Percentage(25),
                            Constraint::Percentage(25),
                            Constraint::Percentage(10),
                        ].as_slice()
                    } else {
                        [
                            Constraint::Percentage(25),
                            Constraint::Percentage(25),
                            Constraint::Percentage(25),
                            Constraint::Percentage(25),
                        ].as_slice()
                    };
                    let table = Table::new(rows, widths)
                        .header(header)
                        .block(Block::default().borders(Borders::ALL).title("Processes"));
                    f.render_widget(table, chunks[1]);
                    
                    let footer_text = if app.containers_mode {
                        "Press 'q' to quit, 'p'/'n'/'s'/'r'/'c' to sort"
                    } else {
                        "Press 'q' to quit, 'p'/'n'/'s'/'r' to sort"
                    };
                    let footer = Paragraph::new(footer_text)
                        .block(Block::default().borders(Borders::ALL));
                    f.render_widget(footer, chunks[2]);
                })?;

                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('q') => break,
                            KeyCode::Char('p') => app.sort_by = SortColumn::Pid,
                            KeyCode::Char('n') => app.sort_by = SortColumn::Name,
                            KeyCode::Char('s') => app.sort_by = SortColumn::Sent,
                            KeyCode::Char('r') => app.sort_by = SortColumn::Received,
                            KeyCode::Char('c') => {
                                if app.containers_mode {
                                    app.sort_by = SortColumn::Container;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            
            restore_terminal(&mut terminal)?;
        }
    } else {
        eprintln!("❌ No interface specified!");
        eprintln!();
        eprintln!("💡 Usage examples:");
        eprintln!("   sudo monitetoring --iface eth0                    # Monitor eth0 interface");
        eprintln!("   sudo monitetoring --iface wlan0 --containers      # Monitor with container awareness");
        eprintln!("   sudo monitetoring --iface any --json              # JSON output from all interfaces");
        eprintln!();
        eprintln!("🔌 Available network interfaces:");
        let devices = match Device::list() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error listing devices: {}", e);
                process::exit(1);
            }
        };
        for device in devices {
            eprintln!("   - {}", device.name);
        }
        eprintln!();
        eprintln!("📖 Use --help for more options");
    }
    Ok(())
}

fn connection_from_packet(packet_data: &[u8]) -> Option<Connection> {
    use etherparse::{SlicedPacket, InternetSlice, TransportSlice};

    // Try Ethernet first (for regular interfaces)
    let sliced = if let Ok(sliced) = SlicedPacket::from_ethernet(packet_data) {
        sliced
    } else {
        // For "any" interface, try IP directly
        SlicedPacket::from_ip(packet_data).ok()?
    };

    let Some(net) = sliced.net else { return None };

    let (source_ip, dest_ip, protocol) = match net {
        InternetSlice::Ipv4(ipv4) => (
            ipv4.header().source_addr().into(),
            ipv4.header().destination_addr().into(),
            ipv4.header().protocol(),
        ),
        InternetSlice::Ipv6(ipv6) => (
            ipv6.header().source_addr().into(),
            ipv6.header().destination_addr().into(),
            ipv6.header().next_header(),
        ),
    };

    let Some(transport) = sliced.transport else { return None };

    let (source_port, dest_port) = match transport {
        TransportSlice::Tcp(tcp) => (tcp.source_port(), tcp.destination_port()),
        TransportSlice::Udp(udp) => (udp.source_port(), udp.destination_port()),
        _ => return None,
    };

    Some(Connection {
        source_port,
        dest_port,
        source_ip,
        dest_ip,
        protocol: protocol.into(),
    })
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>, io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), io::Error> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}
