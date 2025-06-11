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
}

enum SortColumn {
    Pid,
    Name,
    Sent,
    Received,
}

struct App {
    stats: HashMap<i32, ProcessInfo>,
    sort_by: SortColumn,
}

impl App {
    fn new() -> Self {
        App {
            stats: HashMap::new(),
            sort_by: SortColumn::Pid,
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
        }
        sorted
    }
}

#[derive(Clone)]
struct ProcessIdentifier {
    pid: i32,
    name: String,
}

fn refresh_proc_maps() -> (HashMap<u64, ProcessIdentifier>, HashMap<Connection, u64>) {
    let mut inode_to_pid_map: HashMap<u64, ProcessIdentifier> = HashMap::new();
    let mut connection_to_inode_map: HashMap<Connection, u64> = HashMap::new();

    if let Ok(all_procs) = procfs::process::all_processes() {
        for proc in all_procs {
            if let Ok(p) = proc {
                let name = p.stat().map_or_else(|_| "???".to_string(), |s| s.comm);
                if let Ok(fds) = p.fd() {
                    for fd in fds {
                        if let Ok(fd_info) = fd {
                            if let procfs::process::FDTarget::Socket(inode) = fd_info.target {
                                inode_to_pid_map.insert(inode, ProcessIdentifier { pid: p.pid, name: name.clone() });
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
            let (mut inode_map, mut conn_map) = refresh_proc_maps();
            
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
                    (inode_map, conn_map) = refresh_proc_maps();
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
                                    received: 0 
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
            if let Some(final_stats) = rx.recv().await {
                if let Ok(json_output) = serde_json::to_string_pretty(&final_stats) {
                    println!("{}", json_output);
                }
            }
        } else {
            // This will be the UI task
            let mut app = App::new();
            let mut terminal = setup_terminal()?;
            
            loop {
                if let Ok(new_stats) = rx.try_recv() {
                    // Accumulate new data instead of replacing
                    for (pid, new_info) in new_stats {
                        let stats = app.stats.entry(pid).or_insert(ProcessInfo { name: new_info.name.clone(), sent: 0, received: 0 });
                        stats.sent = new_info.sent;
                        stats.received = new_info.received;
                        stats.name = new_info.name;
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

                    let header_cells = ["(P)ID", "Name", "(S)ent", "(R)eceived"]
                        .iter()
                        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Red)));
                    let header = Row::new(header_cells);

                    let rows = app.sorted_stats().into_iter().map(|(pid, data)| {
                        Row::new(vec![
                            Cell::from(pid.to_string()),
                            Cell::from(data.name.clone()),
                            Cell::from(data.sent.to_string()),
                            Cell::from(data.received.to_string()),
                        ])
                    });

                    let widths = [
                        Constraint::Percentage(25),
                        Constraint::Percentage(25),
                        Constraint::Percentage(25),
                        Constraint::Percentage(25),
                    ];
                    let table = Table::new(rows, widths)
                        .header(header)
                        .block(Block::default().borders(Borders::ALL).title("Processes"));
                    f.render_widget(table, chunks[1]);
                    
                    let footer = Paragraph::new("Press 'q' to quit, 'p'/'n'/'s'/'r' to sort")
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
                            _ => {}
                        }
                    }
                }
            }
            
            restore_terminal(&mut terminal)?;
        }
    } else {
        println!("No interface specified. Available interfaces:");
        let devices = match Device::list() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error listing devices: {}", e);
                process::exit(1);
            }
        };
        for device in devices {
            println!("- {}", device.name);
        }
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
