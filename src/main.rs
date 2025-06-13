mod types;
mod config;
mod process;
mod capture;
mod ui;
mod interactive;

use clap::Parser;
use pcap::{Device, Capture};
use std::process::{exit, Command};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use tokio::sync::mpsc;
use crossterm::event::{self, Event};
use std::io;
use std::thread;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nix::errno::Errno;

use config::{Cli, reset_config, load_config};
use types::{App, ProcessInfo, Connection, ProcessInfoFormatted, AlertAction, ChartType};
use process::refresh_proc_maps;
use capture::connection_from_packet;
use ui::{setup_terminal, restore_terminal, render_ui, handle_key_event, update_chart_datasets, utils::format_bytes};
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
        AlertAction::CustomCommand(cmd) => {
            let start_time = Instant::now();
            let total_usage = current_sent + current_received;
            
            // Create the execution log entry that shows immediately
            let execution_log_entry = format!(
                "🔧 Executing custom command for {} (PID {}): {} | Usage: {} ({}% over threshold)",
                name, pid, cmd, format_bytes(total_usage),
                ((total_usage as f64 / threshold as f64 - 1.0) * 100.0) as u32
            );
            
            let mut command = Command::new("sh");
            command.arg("-c").arg(cmd)
                .env("MONITETORING_PID", pid.to_string())
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
            }
        };

        let mut bandwidth_map: HashMap<i32, ProcessInfo> = HashMap::new();
        let mut previous_bandwidth_map: HashMap<i32, ProcessInfo> = HashMap::new();
        let mut last_map_refresh = Instant::now();
        let mut last_send = Instant::now();
        let mut last_rate_calc = Instant::now();
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
                                sent_rate: 0,
                                received_rate: 0,
                                container_name: proc_identifier.container_name.clone(),
                                user_name: proc_identifier.user_name.clone(),
                                has_alert: false, // Default value
                                sent_history: Vec::new(),
                                received_history: Vec::new(),
                            });
                            
                            // Determine direction based on which connection matched
                            if matched_conn == conn {
                                // Original packet direction: process is sending data (outbound)
                                stats.sent += packet.data.len() as u64;
                            } else {
                                // Reverse connection matched: process is receiving data (inbound)  
                                stats.received += packet.data.len() as u64;
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
        let mut app = App::new(containers_mode, show_total_columns);
        if let Some(saved_config) = load_config() {
            for alert in saved_config.alerts {
                app.alerts.insert(alert.process_pid, alert);
            }
        }
        let mut terminal = setup_terminal()?;
        
        loop {
            if let Ok(new_stats) = rx.try_recv() {
                // Accumulate new data instead of replacing, but filter out killed processes
                for (pid, new_info) in new_stats {
                    // Skip processes that have been killed
                    if app.killed_processes.contains(&pid) {
                        continue;
                    }
                    
                    let has_alert = app.alerts.contains_key(&pid);
                    let stats = app.stats.entry(pid).or_insert(ProcessInfo {
                        name: new_info.name.clone(),
                        sent: 0,
                        received: 0,
                        sent_rate: 0,
                        received_rate: 0,
                        container_name: new_info.container_name.clone(),
                        user_name: new_info.user_name.clone(),
                        has_alert,
                        sent_history: Vec::new(),
                        received_history: Vec::new(),
                    });
                    stats.sent = new_info.sent;
                    stats.received = new_info.received;
                    stats.sent_rate = new_info.sent_rate;
                    stats.received_rate = new_info.received_rate;
                    stats.name = new_info.name;
                    stats.container_name = new_info.container_name;
                    stats.user_name = new_info.user_name;
                    stats.has_alert = has_alert;

                    let now = app.start_time.elapsed().as_secs_f64();
                    stats.sent_history.push((now, new_info.sent_rate as f64));
                    stats.received_history.push((now, new_info.received_rate as f64));

                    // Retain only the last 10 minutes of history to avoid unbounded growth
                    let cutoff = now - 600.0; // 600s = 10 min
                    stats.sent_history.retain(|(t, _)| *t >= cutoff);
                    stats.received_history.retain(|(t, _)| *t >= cutoff);
                    


                    // Update system-wide bandwidth history (moved outside the loop for efficiency)
                }
                
                // Update system-wide bandwidth history once per batch
                let now = app.start_time.elapsed().as_secs_f64();
                let cutoff = now - 600.0; // 600s = 10 min
                
                let current_system_snapshot: Vec<(i32, f64, f64)> = app.stats.iter()
                    .map(|(pid, info)| (*pid, info.sent_rate as f64, info.received_rate as f64))
                    .collect();
                app.system_bandwidth_history.push((now, current_system_snapshot));
                
                // Retain only last 10 minutes of system history
                app.system_bandwidth_history.retain(|(t, _)| *t >= cutoff);

                // Update chart datasets for stacked view (only when needed)
                if app.bandwidth_mode && app.chart_type == ChartType::SystemStacked {
                    update_chart_datasets(&mut app);
                }
                
                // Remove killed processes from the stats entirely
                app.stats.retain(|pid, _| !app.killed_processes.contains(pid));
                
                // Update system overview statistics
                app.update_system_stats();
            }

            // Check for triggered alerts (with cooldown)
            let mut processes_to_kill = Vec::new();
            let now = Instant::now();
            const COOLDOWN_DURATION: Duration = Duration::from_secs(60); // 1 minute cooldown
            
            for (pid, alert) in &app.alerts {
                if let Some(stats) = app.stats.get(pid) {
                    if stats.sent + stats.received > alert.threshold_bytes {
                        // Check if alert is in cooldown
                        let should_trigger = match app.alert_cooldowns.get(pid) {
                            Some(last_trigger) => now.duration_since(*last_trigger) >= COOLDOWN_DURATION,
                            None => true, // First time triggering
                        };
                        
                        if should_trigger {
                            // For custom commands, add execution log entry immediately before execution
                            if let AlertAction::CustomCommand(cmd) = &alert.action {
                                let total_usage = stats.sent + stats.received;
                                let execution_log_entry = format!(
                                    "Command execution for {} (PID {}):\n{} | Usage: {} ({}% over threshold)",
                                    &stats.name, *pid, cmd, format_bytes(total_usage),
                                    ((total_usage as f64 / alert.threshold_bytes as f64 - 1.0) * 100.0) as u32
                                );
                                app.command_execution_log.push((now, execution_log_entry));
                                // Keep only the last 50 log entries to prevent unbounded growth
                                if app.command_execution_log.len() > 50 {
                                    app.command_execution_log.remove(0);
                                }
                            }
                            
                            let (was_killed, message, _) = execute_alert_action(&alert.action, *pid, &stats.name, stats.sent, stats.received, alert.threshold_bytes);
                            if was_killed {
                                processes_to_kill.push(*pid);
                            }
                            app.last_alert_message = message;
                            
                            // Set cooldown
                            app.alert_cooldowns.insert(*pid, now);
                        }
                    }
                }
            }
            
            // Mark killed processes and remove their cooldowns
            for pid in processes_to_kill {
                app.killed_processes.insert(pid);
                app.alert_cooldowns.remove(&pid);
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



