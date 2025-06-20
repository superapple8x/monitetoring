mod types;
mod config;
mod process;
mod capture;
mod ui;
mod interactive;
mod dependencies;

use clap::Parser;

use std::process::{exit, Command};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use tokio::sync::mpsc;
use crossterm::event::{self, Event};
use std::io;
use std::thread;
#[cfg(target_os = "linux")]
use nix::sys::signal::{self, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use nix::errno::Errno;

use config::{Cli, reset_config, load_config};
use types::{App, ProcessInfo, Connection, ProcessInfoFormatted, AlertAction, PROCESS_CLEANUP_INTERVAL_SECS};
use process::{refresh_proc_maps, cleanup_dead_processes};
use capture::connection_from_packet;
use ui::utils::format_bytes;
use interactive::run_interactive_mode;

fn display_startup_info(iface: &str, is_json: bool, containers_enabled: bool) {
    eprintln!("🚀 Starting monitetoring...");
    eprintln!("📡 Interface: {}", iface);
    eprintln!("📊 Mode: {}", if is_json { "JSON output" } else { "Interactive TUI" });
    eprintln!("🐳 Container awareness: {}", if containers_enabled { "Enabled" } else { "Disabled" });
    if !is_json {
        eprintln!("⏱️  Preparing to capture network traffic... (Press 'q' to quit)");
        eprintln!();
        eprintln!("🎯 Tip: Press 'p' for PID, 'n' for Name, 'u' for User, 's' for Sent, 'r' for Received{}", 
                 if containers_enabled { ", 'c' for Container" } else { ""});
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
    let devices = match dependencies::DependencyChecker::list_devices_with_dependency_check() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };
    for device in devices {
        eprintln!("   - {}", device.name);
    }
    eprintln!();
    eprintln!("📖 Use --help for more options");
}

fn execute_alert_action(action: &AlertAction, pid: i32, name: &str, current_sent: u64, current_received: u64, threshold: u64) -> (bool, Option<String>, Option<String>) {
    match action {
        AlertAction::SystemAlert => {
            // Just return a notification message, no process killing
            (false, Some(format!("🚨 System Alert for {} (PID {}):\nExceeded bandwidth threshold", name, pid)), None)
        }
        AlertAction::Kill => {
            #[cfg(target_os = "linux")]
            {
                // First, send the kill signal
                match signal::kill(Pid::from_raw(pid), Signal::SIGKILL) {
                    Ok(_) => {
                        // Signal sent, now verify process termination
                    }
                    Err(e) if e == Errno::ESRCH => {
                        // Process already doesn't exist, which is a success in this context
                        return (true, Some(format!("💀 Process {} (PID {}) was already gone", name, pid)), None);
                    }
                    Err(e) => {
                        // Another error, like permissions
                        return (false, Some(format!("❌ Failed to send kill signal to {} (PID {}): {}", name, pid, e)), None);
                    }
                }

                // Poll for up to 2 seconds to see if the process terminates
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(2) {
                    // Check if process exists by sending signal 0
                    match signal::kill(Pid::from_raw(pid), None) {
                        Ok(_) => {
                            // Process still exists, wait a bit
                            thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) if e == Errno::ESRCH => {
                            // Process does not exist, success!
                            return (true, Some(format!("💀 Killed {} (PID {}) due to bandwidth limit", name, pid)), None);
                        }
                        Err(_) => {
                            // Some other error, assume failure to check
                            break;
                        }
                    }
                }

                // If the loop finishes and we haven't returned, the process is still alive
                (false, Some(format!("❌ Failed to kill {} (PID {}): Process still running", name, pid)), None)
            }
            
            #[cfg(target_os = "windows")]
            {
                // Use taskkill command on Windows
                let output = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .stdout(std::process::Stdio::null()) // Suppress stdout
                    .stderr(std::process::Stdio::null()) // Suppress stderr
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        (true, Some(format!("💀 Killed {} (PID {}) due to bandwidth limit", name, pid)), None)
                    }
                    Ok(result) => {
                        let _stderr_msg = String::from_utf8_lossy(&result.stderr);
                        (false, Some(format!("❌ Failed to kill {} (PID {}): taskkill command failed", name, pid)), None)
                    }
                    Err(e) => {
                        (false, Some(format!("❌ Failed to execute taskkill for {} (PID {}): {}", name, pid, e)), None)
                    }
                }
            }
        }
        AlertAction::CustomCommand(cmd) => {
            let start_time = Instant::now();
            let total_usage = current_sent + current_received;
            
            // Create the execution log entry that shows immediately
            let execution_log_entry = format!(
                "🔧 Executing custom command for {} (PID {}): {} | Usage: {} ({}% over threshold)",
                name, pid, cmd, format_bytes(total_usage),
                ((total_usage as f64 / threshold as f64 - 1.0) * 100.0) as u32
            );
            
            #[cfg(target_os = "linux")]
            let mut command = {
                let mut cmd_builder = Command::new("sh");
                cmd_builder.arg("-c").arg(cmd);
                cmd_builder
            };
            
            #[cfg(target_os = "windows")]
            let mut command = {
                let mut cmd_builder = Command::new("cmd");
                cmd_builder.arg("/C").arg(cmd);
                cmd_builder
            };
            
            command.env("MONITETORING_PID", pid.to_string())
                .env("MONITETORING_PROCESS_NAME", name)
                .env("MONITETORING_BANDWIDTH_EXCEEDED", "true")
                .env("MONITETORING_SENT_BYTES", current_sent.to_string())
                .env("MONITETORING_RECEIVED_BYTES", current_received.to_string())
                .env("MONITETORING_TOTAL_BYTES", total_usage.to_string())
                .env("MONITETORING_THRESHOLD_BYTES", threshold.to_string())
                .env("MONITETORING_EXCESS_BYTES", (total_usage.saturating_sub(threshold)).to_string())
                .env("MONITETORING_TIMESTAMP", chrono::Utc::now().to_rfc3339());
            
            // Use spawn() with timeout instead of status() for better control
            match command.spawn() {
                Ok(mut child) => {
                    // Wait for the process with a timeout
                    let timeout_duration = Duration::from_secs(30); // 30 second timeout
                    let poll_start = Instant::now();
                    
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                let execution_time = start_time.elapsed();
                                if status.success() {
                                    return (false, Some(format!(
                                        "✅ Custom command executed successfully for {} (PID {}) in {:.2}s:\nUsage: {} ({}% over threshold)", 
                                        name, pid, execution_time.as_secs_f64(),
                                        format_bytes(total_usage),
                                        ((total_usage as f64 / threshold as f64 - 1.0) * 100.0) as u32
                                    )), Some(execution_log_entry));
                                } else {
                                    return (false, Some(format!(
                                        "❌ Custom command failed (exit code: {}) for {} (PID {}) after {:.2}s:\nUsage: {}", 
                                        status.code().unwrap_or(-1), name, pid, 
                                        execution_time.as_secs_f64(), format_bytes(total_usage)
                                    )), Some(execution_log_entry));
                                }
                            }
                            Ok(None) => {
                                // Process is still running
                                if poll_start.elapsed() > timeout_duration {
                                    // Timeout reached, kill the child process
                                    let _ = child.kill();
                                    let _ = child.wait(); // Clean up zombie
                                    return (false, Some(format!(
                                        "⏰ Custom command timed out after {}s for {} (PID {}):\nUsage: {}", 
                                        timeout_duration.as_secs(), name, pid, format_bytes(total_usage)
                                    )), Some(execution_log_entry));
                                }
                                // Sleep briefly before checking again
                                thread::sleep(Duration::from_millis(100));
                            }
                            Err(e) => {
                                return (false, Some(format!(
                                    "❌ Error waiting for custom command for {} (PID {}):\n{} | Usage: {}", 
                                    name, pid, e, format_bytes(total_usage)
                                )), Some(execution_log_entry));
                            }
                        }
                    }
                }
                Err(e) => {
                    (false, Some(format!(
                        "❌ Failed to spawn custom command for {} (PID {}):\n{} | Usage: {}", 
                        name, pid, e, format_bytes(total_usage)
                    )), Some(execution_log_entry))
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // CRITICAL: Check dependencies FIRST, before any pcap functions are called
    // This prevents crashes when wpcap.dll/npcap is missing on Windows
    #[cfg(target_os = "windows")]
    {
        let missing_deps = dependencies::DependencyChecker::check_dependencies();
        if !missing_deps.is_empty() {
            println!();
            dependencies::DependencyChecker::display_installation_guides(&missing_deps);
            match dependencies::DependencyChecker::prompt_installation_action() {
                Ok(true) => {
                    println!("👋 Run monitetoring again after installing the required dependencies!");
                    exit(0);
                }
                Ok(false) => {
                    println!("⚠️  Continuing without all dependencies - some features may not work properly.");
                    println!();
                }
                Err(e) => {
                    eprintln!("Error handling user input: {}", e);
                    exit(1);
                }
            }
        }
    }

    let cli = Cli::parse();

    // Collect startup warnings to display in the UI once it launches
    let mut startup_warning: Option<String> = None;

    // Check for root privileges on Linux
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("❌ Root privileges required on Linux!");
            eprintln!();
            eprintln!("This tool needs to capture network packets, which requires root access.");
            eprintln!("Please run with sudo:");
            eprintln!("  sudo {}", std::env::args().collect::<Vec<_>>().join(" "));
            eprintln!();
            std::process::exit(1);
        }
    }

    // Check for administrator privileges on Windows
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("net").args(["session"]).output();
        match output {
            Ok(result) if result.status.success() => {
                // Administrator – nothing to do
            }
            _ => {
                // Not admin – store warning to propagate to UI later
                startup_warning = Some("⚠️ Not running as Administrator. Some features may not work".to_string());
            }
        }
    }

    // Check packet capture availability early (Windows needs Npcap)
    if let Err(error_message) = process::check_packet_capture_available() {
        // Use the new dependency system for better user experience
        let missing_deps = dependencies::DependencyChecker::check_dependencies();
        if !missing_deps.is_empty() {
            println!();
            dependencies::DependencyChecker::display_installation_guides(&missing_deps);
            match dependencies::DependencyChecker::prompt_installation_action() {
                Ok(true) => {
                    // User chose to see guides and exit
                    println!("👋 Run monitetoring again after installing the required dependencies!");
                    exit(0);
                }
                Ok(false) => {
                    // User chose to skip and continue anyway
                    eprintln!("⚠️  Continuing without all dependencies - packet capture may not work properly.");
                    eprintln!("Original error: {}", error_message);
                    eprintln!();
                }
                Err(e) => {
                    eprintln!("Error handling user input: {}", e);
                    exit(1);
                }
            }
        } else {
            // Fallback to original error if dependency checker didn't find issues
            eprintln!("{}", error_message);
            exit(1);
        }
    }

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
    let (iface, json_mode, containers_mode, show_total_columns) = if cli.iface.is_none() && !cli.json && !cli.containers {
        // No arguments provided, run interactive mode
        match run_interactive_mode()? {
            Some(config) => (config.interface, config.json_mode, config.containers_mode, config.show_total_columns),
            None => {
                // User cancelled or quit
                return Ok(());
            }
        }
    } else if let Some(iface) = cli.iface {
        // Arguments provided, use them (default show_total_columns to false)
        (iface, cli.json, cli.containers, false)
    } else {
        // Some arguments provided but no interface - show help
        show_interface_help();
        return Ok(());
    };

    // Apply Windows-specific override (disable container awareness)
    let containers_mode_effective = if cfg!(windows) { false } else { containers_mode };

    // Now proceed with the monitoring logic using the determined configuration
    let (tx, mut rx) = mpsc::channel(100);

    // Spawn packet capture thread
    let iface_clone = iface.clone();
    thread::spawn(move || {
        let main_device = match dependencies::DependencyChecker::device_from_name_with_dependency_check(&iface_clone) {
            Ok(device) => device,
            Err(e) => {
                eprintln!("{}", e);
                exit(1);
            }
        };
        
        let cap = match dependencies::DependencyChecker::capture_from_device_with_dependency_check(main_device) {
            Ok(cap) => cap,
            Err(e) => {
                eprintln!("{}", e);
                eprintln!();
                eprintln!("💡 This might be due to:");
                #[cfg(target_os = "windows")]
                eprintln!("   • Missing or improperly installed Npcap/WinPcap");
                #[cfg(target_os = "linux")]
                eprintln!("   • Insufficient permissions (try running with sudo)");
                eprintln!("   • Network interface not available or already in use");
                eprintln!("   • Firewall or security software blocking packet capture");
                eprintln!();
                #[cfg(target_os = "windows")]
                eprintln!("🔧 Try installing Npcap from: https://npcap.com/");
                #[cfg(target_os = "linux")]
                eprintln!("🔧 Try: sudo setcap cap_net_raw,cap_net_admin=eip ./monitetoring");
                exit(1);
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
                eprintln!("❌ Error opening packet capture: {}", e);
                eprintln!();
                eprintln!("💡 Common solutions:");
                #[cfg(target_os = "windows")]
                {
                    eprintln!("   • Make sure you're running as Administrator");
                    eprintln!("   • Install Npcap from: https://npcap.com/");
                    eprintln!("   • Ensure Npcap service is running");
                }
                #[cfg(target_os = "linux")]
                {
                    eprintln!("   • Run with sudo: sudo ./monitetoring --iface {}", iface_clone);
                    eprintln!("   • Set capabilities: sudo setcap cap_net_raw,cap_net_admin=eip ./monitetoring");
                    eprintln!("   • Check if interface exists: ip link show");
                }
                eprintln!("   • Try a different network interface");
                eprintln!("   • Check if another packet capture tool is running");
                exit(1);
            }
        };

        let mut bandwidth_map: HashMap<i32, ProcessInfo> = HashMap::new();
        let mut previous_bandwidth_map: HashMap<i32, ProcessInfo> = HashMap::new();
        let mut last_map_refresh = Instant::now();
        let mut last_send = Instant::now();
        let mut last_rate_calc = Instant::now();
        let (mut inode_map, mut conn_map) = refresh_proc_maps(containers_mode_effective);
        
        let capture_start = Instant::now();

        loop {
            // In JSON mode, run for a limited time (e.g., 5 seconds) then exit thread
            if json_mode && capture_start.elapsed() > Duration::from_secs(5) {
                let _ = tx.blocking_send(bandwidth_map.clone());
                break;
            }

            // Refresh process maps every 2 seconds
            if last_map_refresh.elapsed() > Duration::from_secs(2) {
                (inode_map, conn_map) = refresh_proc_maps(containers_mode_effective);
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
                            // Skip if this process is known to be dead (avoids constant re-adding)
                            // Note: We'll refresh this cache periodically in the main loop
                            let pid = proc_identifier.pid;
                            
                            let stats = bandwidth_map.entry(pid).or_insert(ProcessInfo {
                                name: proc_identifier.name.clone(),
                                sent: 0,
                                received: 0,
                                sent_rate: 0,
                                received_rate: 0,
                                container_name: proc_identifier.container_name.clone(),
                                user_name: proc_identifier.user_name.clone(),
                                has_alert: false, // Default value
                                sent_history: Vec::new(),
                                received_history: Vec::new(),
                                packet_history: std::collections::VecDeque::new(),
                            });
                            
                            // Determine direction based on which connection matched
                            if matched_conn == conn {
                                // Original packet direction: process is sending data (outbound)
                                stats.sent += packet.data.len() as u64;
                                // Record individual packet information for history view
                                {
                                    use crate::types::{PacketInfo, PacketDirection, MAX_PACKET_HISTORY};
                                    let ts_now = std::time::SystemTime::now();
                                    let dt: chrono::DateTime<chrono::Local> = ts_now.into();
                                    let cached_ts = dt.format("%H:%M:%S%.3f").to_string();
                                    let cached_src = format!("{}:{}", conn.source_ip, conn.source_port);
                                    let cached_dst = format!("{}:{}", conn.dest_ip, conn.dest_port);
                                    let cached_proto = match conn.protocol {
                                        6 => "TCP".to_string(),
                                        17 => "UDP".to_string(),
                                        1 => "ICMP".to_string(),
                                        other => other.to_string(),
                                    };
                                    let cached_size = format_bytes(packet.data.len() as u64);

                                    let pinfo = PacketInfo {
                                        timestamp: ts_now,
                                        direction: PacketDirection::Sent,
                                        protocol: conn.protocol,
                                        src_ip: conn.source_ip,
                                        src_port: conn.source_port,
                                        dst_ip: conn.dest_ip,
                                        dst_port: conn.dest_port,
                                        size: packet.data.len(),
                                        cached_ts,
                                        cached_src,
                                        cached_dst,
                                        cached_proto,
                                        cached_size,
                                    };
                                    if stats.packet_history.len() >= MAX_PACKET_HISTORY {
                                        stats.packet_history.pop_front();
                                    }
                                    stats.packet_history.push_back(pinfo);
                                }
                            } else {
                                // Reverse connection matched: process is receiving data (inbound)  
                                stats.received += packet.data.len() as u64;
                                {
                                    use crate::types::{PacketInfo, PacketDirection, MAX_PACKET_HISTORY};
                                    let ts_now = std::time::SystemTime::now();
                                    let dt: chrono::DateTime<chrono::Local> = ts_now.into();
                                    let cached_ts = dt.format("%H:%M:%S%.3f").to_string();
                                    let cached_src = format!("{}:{}", conn.dest_ip, conn.dest_port);
                                    let cached_dst = format!("{}:{}", conn.source_ip, conn.source_port);
                                    let cached_proto = match conn.protocol {
                                        6 => "TCP".to_string(),
                                        17 => "UDP".to_string(),
                                        1 => "ICMP".to_string(),
                                        other => other.to_string(),
                                    };
                                    let cached_size = format_bytes(packet.data.len() as u64);

                                    let pinfo = PacketInfo {
                                        timestamp: ts_now,
                                        direction: PacketDirection::Received,
                                        protocol: conn.protocol,
                                        src_ip: conn.dest_ip,
                                        src_port: conn.dest_port,
                                        dst_ip: conn.source_ip,
                                        dst_port: conn.source_port,
                                        size: packet.data.len(),
                                        cached_ts,
                                        cached_src,
                                        cached_dst,
                                        cached_proto,
                                        cached_size,
                                    };
                                    if stats.packet_history.len() >= MAX_PACKET_HISTORY {
                                        stats.packet_history.pop_front();
                                    }
                                    stats.packet_history.push_back(pinfo);
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Timeout or other error, continue
                }
            }

            // Calculate rates every second
            if last_rate_calc.elapsed() > Duration::from_secs(1) {
                let rate_interval = last_rate_calc.elapsed().as_secs_f64();
                
                for (pid, current_stats) in bandwidth_map.iter_mut() {
                    if let Some(prev_stats) = previous_bandwidth_map.get(pid) {
                        let sent_diff = current_stats.sent.saturating_sub(prev_stats.sent);
                        let received_diff = current_stats.received.saturating_sub(prev_stats.received);
                        
                        current_stats.sent_rate = (sent_diff as f64 / rate_interval) as u64;
                        current_stats.received_rate = (received_diff as f64 / rate_interval) as u64;
                    } else {
                        // First measurement, rate is total divided by time since start
                        let elapsed = capture_start.elapsed().as_secs_f64();
                        if elapsed > 0.0 {
                            current_stats.sent_rate = (current_stats.sent as f64 / elapsed) as u64;
                            current_stats.received_rate = (current_stats.received as f64 / elapsed) as u64;
                        }
                    }
                }
                
                // Store current state for next rate calculation
                previous_bandwidth_map = bandwidth_map.clone();
                last_rate_calc = Instant::now();
            }

            // Send data to the UI thread more frequently for a smoother experience
            if !json_mode && last_send.elapsed() > Duration::from_millis(100) {
                match tx.try_send(bandwidth_map.clone()) {
                    Ok(_) => {
                last_send = Instant::now();
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // Channel full – drop the update, UI will catch up and we send a fresh snapshot later
                    }
                    Err(_) => {
                        // Receiver gone; exit capture loop
                        break;
                    }
                }
            }
        }
    });

    if json_mode {
        display_startup_info(&iface, true, containers_mode_effective);
        
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
        display_startup_info(&iface, false, containers_mode_effective);
        
        // Small delay to let user read the information
        std::thread::sleep(std::time::Duration::from_millis(1500));
        
        // Start TUI
        let mut app = App::new(containers_mode_effective, show_total_columns);
        if let Some(warning) = startup_warning.take() {
            app.kill_notification = Some(warning);
            app.kill_notification_time = Some(Instant::now());
        }
        if let Some(saved_config) = load_config() {
            for alert in saved_config.alerts {
                app.alerts.insert(alert.process_pid, alert);
            }
        }
        let mut terminal = ui::setup_terminal()?;

        let tick_rate = Duration::from_millis(100);
        let mut last_tick = Instant::now();
        let mut last_cleanup = Instant::now();
        
        loop {
            // --- Draw UI ---
            ui::render_ui(&mut app, &mut terminal)?;
            
            // Reset force redraw flag after rendering
            if app.force_redraw {
                app.force_redraw = false;
            }

            // --- Input Handling ---
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if crossterm::event::poll(timeout)? {
                if let Event::Key(event) = event::read()? {
                    if event.kind == crossterm::event::KeyEventKind::Press {
                        if ui::input::handle_key_event(&mut app, event.code) {
                            break; // Exit condition
                        }
                    }
                }
            }
            
            // --- Tick-based updates ---
            if last_tick.elapsed() >= tick_rate {
                // Drain all pending messages and only keep the most recent to avoid backlog lag
                let mut latest_stats = None;
                while let Ok(stats) = rx.try_recv() {
                    latest_stats = Some(stats);
                }

                if let Some(new_stats) = latest_stats {
                    let now = app.start_time.elapsed().as_secs_f64();
                    for (pid, new_info) in new_stats {
                        // Ignore stats for processes that are known to be killed or dead
                        if !process::should_track_process(pid, &app.killed_processes, &app.dead_processes_cache) {
                            continue;
                        }
                        let entry = app.stats.entry(pid).or_insert_with(|| {
                            // If process is new, create a new ProcessInfo for it
                            let mut pi = new_info.clone();
                            // Allocate enough space for ~5 minutes of data for history vectors
                            pi.sent_history = Vec::with_capacity(3_100);
                            pi.received_history = Vec::with_capacity(3_100);
                            pi
                        });

                        // Update stats from the capture thread
                        entry.sent = new_info.sent;
                        entry.received = new_info.received;
                        entry.sent_rate = new_info.sent_rate;
                        entry.received_rate = new_info.received_rate;
                        entry.name = new_info.name;
                        entry.packet_history = new_info.packet_history;

                        // Update the per-process history for the chart
                        entry.sent_history.push((now, entry.sent_rate as f64));
                        entry.received_history.push((now, entry.received_rate as f64));

                        // Trim history vectors to prevent them from growing indefinitely
                        // Keep at most ~5 minutes (≈3 000 points) of history to match the chart window
                        if entry.sent_history.len() > 3_000 {
                            entry.sent_history.remove(0);
                        }
                        if entry.received_history.len() > 3_000 {
                            entry.received_history.remove(0);
                        }
                    }
                }

                // Update data for other UI components that depend on the new stats
                app.update_system_stats();
                let now = app.start_time.elapsed().as_secs_f64();
                let rates: Vec<(i32, f64, f64)> = app.stats.iter()
                    .map(|(pid, info)| (*pid, info.sent_rate as f64, info.received_rate as f64))
                    .collect();
                app.system_bandwidth_history.push((now, rates));
                // Cap system-wide history to ~5 minutes, too (3 000 × 100 ms)
                if app.system_bandwidth_history.len() > 3_000 {
                    app.system_bandwidth_history.remove(0);
                }
                ui::update_chart_datasets(&mut app);

                // Cleanup alerts that have been displayed for more than 5 seconds
                if let Some(time) = app.last_alert_message_time {
                    if time.elapsed() > Duration::from_secs(5) {
                        app.last_alert_message = None;
                        app.last_alert_message_time = None;
                    }
                }

                // Cleanup kill notifications that have been displayed for more than 5 seconds
                if let Some(time) = app.kill_notification_time {
                    if time.elapsed() > Duration::from_secs(5) {
                        app.kill_notification = None;
                        app.kill_notification_time = None;
                    }
                }

                // Cleanup settings notifications that have been displayed for more than 5 seconds
                if let Some(time) = app.settings_notification_time {
                    if time.elapsed() > Duration::from_secs(5) {
                        app.settings_notification = None;
                        app.settings_notification_time = None;
                    }
                }

                // Enhanced export notification cleanup with state management
                if let Some(time) = app.export_notification_time {
                    let elapsed = time.elapsed();
                    if elapsed > Duration::from_secs(9) && elapsed <= Duration::from_secs(10) {
                        // Transition to expiring state for smoother cleanup
                        if app.export_notification_state != types::NotificationState::Expiring {
                            app.export_notification_state = types::NotificationState::Expiring;
                            app.force_redraw = true; // Force redraw on state transition
                        }
                    } else if elapsed > Duration::from_secs(10) {
                        // Complete cleanup
                        app.export_notification_state = types::NotificationState::None;
                        app.export_notification_time = None;
                        app.force_redraw = true; // Force redraw when clearing notification
                    }
                }

                // Check for triggered alerts
                let mut triggered_alerts = Vec::new();
            for (pid, alert) in &app.alerts {
                if let Some(stats) = app.stats.get(pid) {
                        let total_usage = stats.sent + stats.received;
                        if total_usage > alert.threshold_bytes {
                            // Check cooldown
                            let should_trigger = if let Some(last_triggered) = app.alert_cooldowns.get(pid) {
                                last_triggered.elapsed() > Duration::from_secs(60) // 1 minute cooldown
                            } else {
                                true
                        };
                        
                        if should_trigger {
                                triggered_alerts.push((*pid, alert.clone()));
                                app.alert_cooldowns.insert(*pid, Instant::now());
                            }
                        }
                    }
                }
                
                for (pid, alert) in triggered_alerts {
                    if let Some(stats) = app.stats.get(&pid) {
                        let (was_killed, message, execution_log) = execute_alert_action(
                            &alert.action, pid, &stats.name, stats.sent, stats.received, alert.threshold_bytes
                        );
                        
                        if let Some(msg) = message {
                            app.last_alert_message = Some(msg);
                            app.last_alert_message_time = Some(Instant::now());
                        }
                        if let Some(log_entry) = execution_log {
                            app.command_execution_log.push_front((Instant::now(), log_entry));
                            if app.command_execution_log.len() > 10 {
                                app.command_execution_log.pop_back();
                            }
                        }

                        if was_killed {
                            app.killed_processes.insert(pid);
                            app.stats.remove(&pid);
                        }
                    }
                }

                // Periodic cleanup of dead processes
                if last_cleanup.elapsed() >= Duration::from_secs(PROCESS_CLEANUP_INTERVAL_SECS) {
                    let removed_pids = cleanup_dead_processes(&mut app.stats, &app.killed_processes);
                    for pid in removed_pids {
                        app.dead_processes_cache.insert(pid);
                        if app.selected_process == Some(pid) {
                            app.selected_process = None;
                        }
                    }
                    last_cleanup = Instant::now();
                }

                last_tick = Instant::now();
            }
        }
        
        ui::restore_terminal(&mut terminal)?;
    }
    Ok(())
}



