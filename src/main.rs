mod types;
mod config;
mod process;
mod capture;
mod ui;
mod interactive;

use clap::Parser;
use pcap::{Device, Capture};
use std::process::exit;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use tokio::sync::mpsc;
use crossterm::event::{self, Event};
use std::io;
use std::thread;

use config::{Cli, reset_config};
use types::{App, ProcessInfo, Connection, ProcessInfoFormatted};
use process::refresh_proc_maps;
use capture::connection_from_packet;
use ui::{setup_terminal, restore_terminal, render_ui, handle_key_event};
use interactive::{run_interactive_mode, InteractiveConfig};

fn display_startup_info(iface: &str, is_json: bool, containers_enabled: bool) {
    eprintln!("🚀 Starting monitetoring...");
    eprintln!("📡 Interface: {}", iface);
    eprintln!("📊 Mode: {}", if is_json { "JSON output" } else { "Interactive TUI" });
    eprintln!("🐳 Container awareness: {}", if containers_enabled { "Enabled" } else { "Disabled" });
    if !is_json {
        eprintln!("⏱️  Preparing to capture network traffic... (Press 'q' to quit)");
        eprintln!();
        eprintln!("🎯 Tip: Press 'p' for PID, 'n' for Name, 's' for Sent, 'r' for Received{}", 
                 if containers_enabled { ", 'c' for Container" } else { "" });
        eprintln!("📊 Sorting: Higher bandwidth usage appears at the top");
        eprintln!();
    } else {
        eprintln!("⏱️  Capturing for 5 seconds...");
        eprintln!();
    }
}

fn show_interface_help() {
    eprintln!("❌ No interface specified!");
    eprintln!();
    eprintln!("💡 Usage examples:");
    eprintln!("   sudo monitetoring --iface eth0                    # Monitor eth0 interface");
    eprintln!("   sudo monitetoring --iface wlan0 --containers      # Monitor with container awareness");
    eprintln!("   sudo monitetoring --iface any --json              # JSON output from all interfaces");
    eprintln!("   sudo monitetoring --reset                         # Reset saved configuration");
    eprintln!();
    eprintln!("🔌 Available network interfaces:");
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error listing devices: {}", e);
            exit(1);
            unreachable!()
        }
    };
    for device in devices {
        eprintln!("   - {}", device.name);
    }
    eprintln!();
    eprintln!("📖 Use --help for more options");
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let cli = Cli::parse();

    // Handle reset flag first
    if cli.reset {
        match reset_config() {
            Ok(true) => {
                println!("✅ Saved configuration has been reset.");
                println!("   Next time you run the program, you'll see the full setup again.");
            }
            Ok(false) => {
                println!("ℹ️  No saved configuration found to reset.");
            }
            Err(e) => {
                eprintln!("❌ Error resetting configuration: {}", e);
                exit(1);
            }
        }
        return Ok(());
    }

    // Check if no arguments were provided - run interactive mode
    let (iface, json_mode, containers_mode) = if cli.iface.is_none() && !cli.json && !cli.containers {
        // No arguments provided, run interactive mode
        match run_interactive_mode()? {
            Some(config) => (config.interface, config.json_mode, config.containers_mode),
            None => {
                // User cancelled or quit
                return Ok(());
            }
        }
    } else if let Some(iface) = cli.iface {
        // Arguments provided, use them
        (iface, cli.json, cli.containers)
    } else {
        // Some arguments provided but no interface - show help
        show_interface_help();
        return Ok(());
    };

    // Now proceed with the monitoring logic using the determined configuration
    let (tx, mut rx) = mpsc::channel(100);

    // Spawn packet capture thread
    let iface_clone = iface.clone();
    thread::spawn(move || {
        let main_device = Device::from(iface_clone.as_str());
        
        let cap = match Capture::from_device(main_device) {
            Ok(cap) => cap,
            Err(e) => {
                eprintln!("Error creating capture handle: {}", e);
                exit(1);
                unreachable!()
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
                exit(1);
                unreachable!()
            }
        };

        let mut bandwidth_map: HashMap<i32, ProcessInfo> = HashMap::new();
        let mut last_map_refresh = Instant::now();
        let mut last_send = Instant::now();
        let (mut inode_map, mut conn_map) = refresh_proc_maps(containers_mode);
        
        let capture_start = Instant::now();

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
                    if let Some(conn) = connection_from_packet(packet.data) {
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
                        }
                    }
                }
                Err(_) => {
                    // Timeout or other error, continue
                }
            }

            if !json_mode && last_send.elapsed() > Duration::from_secs(1) {
                let _ = tx.blocking_send(bandwidth_map.clone());
                last_send = Instant::now();
            }
        }
    });

    if json_mode {
        display_startup_info(&iface, true, containers_mode);
        
        if let Some(final_stats) = rx.recv().await {
            // Convert to formatted version for JSON output
            let formatted_stats: std::collections::HashMap<i32, ProcessInfoFormatted> = final_stats
                .iter()
                .map(|(pid, info)| (*pid, ProcessInfoFormatted::from(info)))
                .collect();
            
            if let Ok(json_output) = serde_json::to_string_pretty(&formatted_stats) {
                println!("{}", json_output);
            }
        }
    } else {
        display_startup_info(&iface, false, containers_mode);
        
        // Small delay to let user read the information
        std::thread::sleep(std::time::Duration::from_millis(2000));
        
        // Start TUI
        let mut app = App::new(containers_mode);
        let mut terminal = setup_terminal()?;
        
        loop {
            if let Ok(new_stats) = rx.try_recv() {
                // Accumulate new data instead of replacing
                for (pid, new_info) in new_stats {
                    let stats = app.stats.entry(pid).or_insert(ProcessInfo { 
                        name: new_info.name.clone(), 
                        sent: 0, 
                        received: 0, 
                        container_name: new_info.container_name.clone() 
                    });
                    stats.sent = new_info.sent;
                    stats.received = new_info.received;
                    stats.name = new_info.name;
                    stats.container_name = new_info.container_name;
                }
            }
            
            render_ui(&app, &mut terminal)?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if handle_key_event(&mut app, key.code) {
                        break; // User pressed 'q'
                    }
                }
            }
        }
        
        restore_terminal(&mut terminal)?;
    }

    Ok(())
}


