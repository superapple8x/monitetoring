use crossterm::event::KeyCode;
use crate::types::{Alert, AlertAction, App, AppMode, SortColumn, SortDirection, EditingField, ChartType, MetricsMode};
use crate::ui::utils::{parse_input_to_bytes, format_bytes};

#[cfg(target_os = "linux")]
use nix::sys::signal::{self, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;

/// Handle keyboard input events for all application modes
pub fn handle_key_event(app: &mut App, key: crossterm::event::KeyCode) -> bool {
    match app.mode {
        AppMode::EditingAlert => handle_alert_editing_keys(app, key),
        AppMode::Normal => handle_normal_mode_keys(app, key),
        AppMode::SystemOverview => handle_overview_mode_keys(app, key),
        AppMode::Settings => handle_settings_mode_keys(app, key),
        AppMode::PacketDetails => handle_packet_details_mode_keys(app, key),
    }
}

/// Handle key events in alert editing mode
fn handle_alert_editing_keys(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Char(c) => {
            match app.current_editing_field {
                EditingField::Threshold => app.alert_input.push(c),
                EditingField::Command => app.command_input.push(c),
            }
        }
        KeyCode::Backspace => {
            match app.current_editing_field {
                EditingField::Threshold => { app.alert_input.pop(); },
                EditingField::Command => { app.command_input.pop(); },
            }
        }
        KeyCode::Esc => {
            app.mode = AppMode::Normal;
            app.alert_input.clear();
            app.command_input.clear();
        }
        KeyCode::Up => {
            if app.selected_alert_action > 0 {
                app.selected_alert_action -= 1;
            }
        }
        KeyCode::Down => {
            if app.selected_alert_action < 2 {
                app.selected_alert_action += 1;
            }
        }
        KeyCode::Tab => {
            app.current_editing_field = match app.current_editing_field {
                EditingField::Threshold => EditingField::Command,
                EditingField::Command => EditingField::Threshold,
            };
        }
        KeyCode::Enter => {
            if let Some(pid) = app.selected_process {
                let (threshold, action) = match app.selected_alert_action {
                    0 => {
                        // Kill Process - just parse threshold
                        (parse_input_to_bytes(&app.alert_input), AlertAction::Kill)
                    },
                    1 => {
                        // Custom Command - parse "threshold,command" format
                        let threshold = parse_input_to_bytes(&app.alert_input);
                        let command = app.command_input.trim().to_string();
                        if command.is_empty() {
                            (threshold, AlertAction::Kill)
                        } else {
                            (threshold, AlertAction::CustomCommand(command))
                        }
                    },
                    2 => {
                        // Alert - just parse threshold
                        (parse_input_to_bytes(&app.alert_input), AlertAction::SystemAlert)
                    },
                    _ => (1024 * 1024, AlertAction::Kill),
                };
                
                let new_alert = Alert {
                    process_pid: pid,
                    threshold_bytes: threshold,
                    action: action.clone(),
                };
                app.alerts.insert(pid, new_alert);
                
                // Add to system alerts if it's a system alert
                if let AlertAction::SystemAlert = action {
                    app.system_alerts.insert(pid);
                }
            }
            app.mode = AppMode::Normal;
            app.alert_input.clear();
            app.command_input.clear();
        }
        _ => {}
    }
    false
}

/// Handle key events in normal mode
fn handle_normal_mode_keys(app: &mut App, key: KeyCode) -> bool {
    if app.show_action_panel {
        handle_action_panel_keys(app, key)
    } else {
        handle_main_view_keys(app, key)
    }
}

/// Handle key events when action panel is shown
fn handle_action_panel_keys(app: &mut App, key: KeyCode) -> bool {
    let mut num_actions = 3; // Kill, Edit, Details
    if let Some(pid) = app.selected_process {
        if app.alerts.contains_key(&pid) {
            num_actions = 4; // Add Remove option
        }
    }

    match key {
        KeyCode::Esc => {
            app.show_action_panel = false;
            app.selected_action = 0;
        }
        KeyCode::Up | KeyCode::Left => {
            if app.selected_action > 0 {
                app.selected_action -= 1;
            }
        }
        KeyCode::Down | KeyCode::Right => {
            if app.selected_action < num_actions - 1 {
                app.selected_action += 1;
            }
        }
        KeyCode::Enter => {
            if let Some(pid) = app.selected_process {
                let has_alert = app.alerts.contains_key(&pid);
                let action_str = match app.selected_action {
                    0 => "Kill",
                    1 => "Edit",
                    2 => "Details",
                    3 if has_alert => "Remove",
                    _ => "",
                };

                match action_str {
                    "Kill" => {
                        let kill_success = {
                            #[cfg(target_os = "linux")]
                            {
                                signal::kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok()
                            }
                            
                            #[cfg(target_os = "windows")]
                            {
                                use std::process::Command;
                                let output = Command::new("taskkill")
                                    .args(["/PID", &pid.to_string(), "/F"])
                                    .stdout(std::process::Stdio::null()) // Suppress stdout
                                    .stderr(std::process::Stdio::null()) // Suppress stderr
                                    .output();
                                
                                match output {
                                    Ok(result) => result.status.success(),
                                    Err(_) => false,
                                }
                            }
                        };
                        
                        if kill_success {
                            let process_name = app.stats.get(&pid)
                                .map(|info| info.name.clone())
                                .unwrap_or_else(|| format!("PID {}", pid));
                            
                            app.kill_notification = Some(format!("✅ Successfully killed {} (PID {})", process_name, pid));
                            app.kill_notification_time = Some(std::time::Instant::now());
                            
                            // Remove process immediately from stats and alerts
                            app.stats.remove(&pid);
                            app.alerts.remove(&pid);
                            
                            app.killed_processes.insert(pid);
                            app.selected_process = None;
                        } else {
                            app.kill_notification = Some(format!("❌ Failed to kill process (PID {})", pid));
                            app.kill_notification_time = Some(std::time::Instant::now());
                        }
                    }
                    "Edit" => {
                        app.mode = AppMode::EditingAlert;
                        if let Some(alert) = app.alerts.get(&pid) {
                            app.selected_alert_action = match &alert.action {
                                AlertAction::Kill => {
                                    app.alert_input = format_bytes(alert.threshold_bytes);
                                    0
                                },
                                AlertAction::CustomCommand(cmd) => {
                                    app.alert_input = format_bytes(alert.threshold_bytes);
                                    app.command_input = cmd.clone();
                                    1
                                },
                                AlertAction::SystemAlert => {
                                    app.alert_input = format_bytes(alert.threshold_bytes);
                                    2
                                },
                            };
                        } else {
                            app.alert_input.clear();
                            app.selected_alert_action = 0;
                        }
                        app.command_input.clear();
                    }
                    "Details" => {
                        app.mode = AppMode::PacketDetails;
                        app.packet_scroll_offset = 0;
                        app.packet_filter = None;
                    }
                    "Remove" => {
                        app.alerts.remove(&pid);
                        app.system_alerts.remove(&pid);
                    }
                    _ => {}
                }
            }
            app.show_action_panel = false;
            app.selected_action = 0;
        }
        _ => {}
    }
    false
}

/// Handle key events in main view (normal mode without action panel)
fn handle_main_view_keys(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Char('q') => return true,
        KeyCode::Esc => {
            // Dismiss notification boxes when Esc is pressed
            if app.last_alert_message.is_some() || !app.command_execution_log.is_empty() || app.kill_notification.is_some() {
                app.last_alert_message = None;
                app.last_alert_message_time = None;
                app.kill_notification = None;
                app.kill_notification_time = None;
                app.command_execution_log.clear();
            }
        },
        KeyCode::Char('p') => app.sort_by = SortColumn::Pid,
        KeyCode::Char('n') => app.sort_by = SortColumn::Name,
        KeyCode::Char('u') => app.sort_by = SortColumn::User,
        KeyCode::Char('s') => {
            if app.show_total_columns {
                // Cycle between Sent (total) and SentRate when total columns are shown
                app.sort_by = match app.sort_by {
                    SortColumn::Sent => SortColumn::SentRate,
                    SortColumn::SentRate => SortColumn::Sent,
                    _ => SortColumn::Sent, // Default to total sent
                };
            } else {
                // When total columns are not shown, sort by rate (which is the only sent data visible)
                app.sort_by = SortColumn::SentRate;
            }
        },
        KeyCode::Char('r') => {
            if app.show_total_columns {
                // Cycle between Received (total) and ReceivedRate when total columns are shown
                app.sort_by = match app.sort_by {
                    SortColumn::Received => SortColumn::ReceivedRate,
                    SortColumn::ReceivedRate => SortColumn::Received,
                    _ => SortColumn::Received, // Default to total received
                };
            } else {
                // When total columns are not shown, sort by rate (which is the only received data visible)
                app.sort_by = SortColumn::ReceivedRate;
            }
        },
        KeyCode::Char('c') => {
            if app.containers_mode {
                app.sort_by = SortColumn::Container;
            }
        }
        KeyCode::Char('d') => {
            app.sort_direction = if app.sort_direction == SortDirection::Asc {
                SortDirection::Desc
            } else {
                SortDirection::Asc
            };
        }
        KeyCode::Tab => {
            // Cycle through modes: Main -> Bandwidth -> Overview -> Settings -> Main
            if app.mode == AppMode::Settings {
                // Currently in settings mode, go back to normal
                app.mode = AppMode::Normal;
            } else if app.mode == AppMode::SystemOverview {
                // Currently in overview mode, go to settings
                app.mode = AppMode::Settings;
            } else if app.bandwidth_mode {
                // Currently in bandwidth mode, go to overview
                app.mode = AppMode::SystemOverview;
                app.bandwidth_mode = false;
            } else if app.mode == AppMode::Normal {
                // Currently in normal mode, go to bandwidth
                app.bandwidth_mode = true;
                
                // Auto-select first process if none selected (for ProcessLines chart)
                if app.selected_process.is_none() && !app.stats.is_empty() {
                    let sorted_pids: Vec<i32> = app.sorted_stats().iter().map(|(pid, _)| **pid).collect();
                    if !sorted_pids.is_empty() {
                        app.selected_process = Some(sorted_pids[0]);
                    }
                }
            }
        }
        KeyCode::Char('t') => {
            // Toggle chart type only when in bandwidth mode
            if app.bandwidth_mode {
                let old_chart_type = app.chart_type;
                app.chart_type = match app.chart_type {
                    ChartType::ProcessLines => ChartType::SystemStacked,
                    ChartType::SystemStacked => ChartType::ProcessLines,
                };
                // Force chart update only when switching to SystemStacked
                if app.chart_type == ChartType::SystemStacked && old_chart_type != ChartType::SystemStacked {
                    crate::ui::charts::update_chart_datasets(app);
                }
            }
        }
        KeyCode::Char('m') => {
            // Toggle metrics mode only when in bandwidth mode with stacked chart
            if app.bandwidth_mode && app.chart_type == ChartType::SystemStacked {
                app.metrics_mode = match app.metrics_mode {
                    MetricsMode::Combined => MetricsMode::SendOnly,
                    MetricsMode::SendOnly => MetricsMode::ReceiveOnly,
                    MetricsMode::ReceiveOnly => MetricsMode::Combined,
                };
                // Force chart update when changing metrics mode
                crate::ui::charts::update_chart_datasets(app);
            }
        }
        KeyCode::Down => {
            let sorted_pids: Vec<i32> = app.sorted_stats().iter().map(|(pid, _)| **pid).collect();
            if let Some(current_pid) = app.selected_process {
                if let Some(current_index) = sorted_pids.iter().position(|p| *p == current_pid) {
                    if current_index < sorted_pids.len() - 1 {
                        app.selected_process = Some(sorted_pids[current_index + 1]);
                    }
                }
            } else if !sorted_pids.is_empty() {
                app.selected_process = Some(sorted_pids[0]);
            }
        }
        KeyCode::Up => {
            let sorted_pids: Vec<i32> = app.sorted_stats().iter().map(|(pid, _)| **pid).collect();
            if let Some(current_pid) = app.selected_process {
                if let Some(current_index) = sorted_pids.iter().position(|p| *p == current_pid) {
                    if current_index > 0 {
                        app.selected_process = Some(sorted_pids[current_index - 1]);
                    }
                }
            } else if !sorted_pids.is_empty() {
                app.selected_process = Some(sorted_pids[sorted_pids.len() - 1]);
            }
        }
        KeyCode::Enter => {
            if app.selected_process.is_some() {
                app.show_action_panel = true;
                app.selected_action = 0;
            }
        }
        _ => {}
    }
    false
}

/// Handle key events in system overview mode
fn handle_overview_mode_keys(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Char('q') => return true,
        KeyCode::Esc => {
            app.mode = AppMode::Normal;
        }
        KeyCode::Tab => {
            // Cycle from SystemOverview to Settings mode
            app.mode = AppMode::Settings;
        }
        KeyCode::Char('r') => {
            // Reset threshold exceeded state
            app.threshold_exceeded = false;
            app.threshold_exceeded_time = None;
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            // Increase quota by 100MB
            app.total_quota_threshold += 100 * 1024 * 1024;
        }
        KeyCode::Char('-') => {
            // Decrease quota by 100MB (min 100MB)
            if app.total_quota_threshold > 100 * 1024 * 1024 {
                app.total_quota_threshold -= 100 * 1024 * 1024;
            }
        }
        KeyCode::Up => {
            // Scroll up in alert list
            if app.alert_scroll_offset > 0 {
                app.alert_scroll_offset -= 1;
            }
        }
        KeyCode::Down => {
            // Scroll down in alert list
            let max_scroll = app.alerts.len().saturating_sub(1);
            if app.alert_scroll_offset < max_scroll {
                app.alert_scroll_offset += 1;
            }
        }
        _ => {}
    }
    false
}

/// Handle key events in settings mode
fn handle_settings_mode_keys(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Char('q') => return true, // Quit application
        KeyCode::Esc => {
            // Go back to main mode
            app.mode = AppMode::Normal;
        }
        KeyCode::Tab => {
            // Cycle from Settings back to Main mode
            app.mode = AppMode::Normal;
        }
        KeyCode::Up => {
            if app.settings_selected_option > 0 {
                app.settings_selected_option -= 1;
            }
        }
        KeyCode::Down => {
            // We have 2 settings for now
            if app.settings_selected_option < 1 {
                app.settings_selected_option += 1;
            }
        }
        KeyCode::Left => {
            if let Some(mut config) = crate::config::load_config() {
                match app.settings_selected_option {
                    0 => {
                        config.large_packet_threshold = config.large_packet_threshold.saturating_sub(1000);
                    }
                    1 => {
                        config.frequent_connection_threshold = config.frequent_connection_threshold.saturating_sub(1);
                    }
                    _ => {}
                }
                if crate::config::save_config(&config).is_ok() {
                    app.settings_notification = Some("✅ Setting updated.".to_string());
                } else {
                    app.settings_notification = Some("❌ Failed to save setting.".to_string());
                }
                app.settings_notification_time = Some(std::time::Instant::now());
            } else {
                app.settings_notification = Some("ℹ️ No saved configuration to update.".to_string());
                app.settings_notification_time = Some(std::time::Instant::now());
            }
        }
        KeyCode::Right => {
            if let Some(mut config) = crate::config::load_config() {
                match app.settings_selected_option {
                    0 => {
                        config.large_packet_threshold = config.large_packet_threshold.saturating_add(1000);
                    }
                    1 => {
                        config.frequent_connection_threshold = config.frequent_connection_threshold.saturating_add(1);
                    }
                    _ => {}
                }
                 if crate::config::save_config(&config).is_ok() {
                    app.settings_notification = Some("✅ Setting updated.".to_string());
                } else {
                    app.settings_notification = Some("❌ Failed to save setting.".to_string());
                }
                app.settings_notification_time = Some(std::time::Instant::now());
            } else {
                app.settings_notification = Some("ℹ️ No saved configuration to update.".to_string());
                app.settings_notification_time = Some(std::time::Instant::now());
            }
        }
        KeyCode::Char('r') => {
            // Reset configuration
            match crate::config::reset_config() {
                Ok(true) => {
                    app.settings_notification = Some("✅ Configuration removed successfully! Exit and restart the tool to reconfigure.".to_string());
                    app.settings_notification_time = Some(std::time::Instant::now());
                }
                Ok(false) => {
                    app.settings_notification = Some("ℹ️ No saved configuration found to remove.".to_string());
                    app.settings_notification_time = Some(std::time::Instant::now());
                }
                Err(_) => {
                    app.settings_notification = Some("❌ Error removing configuration.".to_string());
                    app.settings_notification_time = Some(std::time::Instant::now());
                }
            }
        }
        _ => {}
    }
    false
}

/// Handle key events in Packet Details view
fn handle_packet_details_mode_keys(app: &mut App, key: KeyCode) -> bool {
    use crossterm::event::KeyCode::*;
    use crate::types::{PacketSortColumn, PacketSortDirection};

    // Handle search input mode first
    if app.packet_search_mode {
        // return handle_packet_search_keys(app, key);
    }

    match key {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.mode = AppMode::Normal;
            // SOLUTION 3: Force a full redraw when leaving packet details
            app.force_redraw = true;
            // Reset notification state when leaving the view to prevent artifacts
            app.export_notification_state = crate::types::NotificationState::None;
            return false;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let filtered_count = app.packet_cache.len();
            if filtered_count > 0 {
                let num_packets = if let Some(pid) = app.selected_process {
                    if let Some(pinfo) = app.stats.get(&pid) {
                        pinfo.packet_history.len()
                    } else { 0 }
                } else { 0 };

                if num_packets > 0 && app.packet_scroll_offset < num_packets - 1 {
                    app.packet_scroll_offset += 1;
                }
            }
        }
        KeyCode::Up => {
            if app.packet_scroll_offset > 0 {
                app.packet_scroll_offset -= 1;
            }
        }
        KeyCode::PageUp => {
            let page = app.packet_visible_rows.max(1);
            if app.packet_scroll_offset >= page {
                app.packet_scroll_offset -= page;
            } else {
                app.packet_scroll_offset = 0;
            }
        }
        KeyCode::PageDown => {
            let num_packets = if let Some(pid) = app.selected_process {
                app.stats.get(&pid).map(|p| p.packet_history.len()).unwrap_or(0)
            } else { 0 };

            let page = app.packet_visible_rows.max(1);
            app.packet_scroll_offset = (app.packet_scroll_offset + page).min(num_packets.saturating_sub(1));
        }
        Char('t') => {
            // Cycle through protocol filters: None -> TCP -> UDP -> None
            if let Some(filter) = &mut app.packet_filter {
                filter.protocol = match filter.protocol {
                    None => Some(6),        // TCP
                    Some(6) => Some(17),    // UDP
                    Some(17) => None,       // Back to All
                    _ => Some(6),           // Default to TCP for other protocols
                };
            } else {
                app.packet_filter = Some(crate::types::PacketFilter { 
                    protocol: Some(6), // Start with TCP
                    direction: None,
                    search_term: None,
                    search_regex: None,
                });
            }
            // Reset scroll when filtering changes
            app.packet_scroll_offset = 0;
        }
        Char('r') => {
            // Cycle through direction filters: None -> Sent -> Received -> None
            if let Some(filter) = &mut app.packet_filter {
                filter.direction = match filter.direction {
                    None => Some(crate::types::PacketDirection::Sent),
                    Some(crate::types::PacketDirection::Sent) => Some(crate::types::PacketDirection::Received),
                    Some(crate::types::PacketDirection::Received) => None,
                };
            } else {
                app.packet_filter = Some(crate::types::PacketFilter { 
                    protocol: None,
                    direction: Some(crate::types::PacketDirection::Sent),
                    search_term: None,
                    search_regex: None,
                });
            }
            // Reset scroll when filtering changes
            app.packet_scroll_offset = 0;
        }
        Char('c') => {
            // Clear all filters
            app.packet_filter = None;
            app.packet_scroll_offset = 0;
        }
        Char('u') => {
            // Quick shortcut for UDP filter
            if let Some(filter) = &mut app.packet_filter {
                filter.protocol = if filter.protocol == Some(17) { None } else { Some(17) };
            } else {
                app.packet_filter = Some(crate::types::PacketFilter { 
                    protocol: Some(17), // UDP
                    direction: None,
                    search_term: None,
                    search_regex: None,
                });
            }
            app.packet_scroll_offset = 0;
        }
        Char('i') => {
            // Quick shortcut for ICMP filter
            if let Some(filter) = &mut app.packet_filter {
                filter.protocol = if filter.protocol == Some(1) { None } else { Some(1) };
            } else {
                app.packet_filter = Some(crate::types::PacketFilter { 
                    protocol: Some(1), // ICMP
                    direction: None,
                    search_term: None,
                    search_regex: None,
                });
            }
            app.packet_scroll_offset = 0;
        }
        Char('s') => {
            // Quick shortcut to filter by Sent packets only
            if let Some(filter) = &mut app.packet_filter {
                filter.direction = if filter.direction == Some(crate::types::PacketDirection::Sent) {
                    None
                } else {
                    Some(crate::types::PacketDirection::Sent)
                };
            } else {
                app.packet_filter = Some(crate::types::PacketFilter { 
                    protocol: None,
                    direction: Some(crate::types::PacketDirection::Sent),
                    search_term: None,
                    search_regex: None,
                });
            }
            app.packet_scroll_offset = 0;
        }
        Char('/') => {
            // Enter search mode
            app.packet_search_mode = true;
            app.packet_search_input.clear();
        }
        Char('1') => {
            // Sort by Timestamp 
            if app.packet_sort_column == PacketSortColumn::Timestamp {
                app.packet_sort_direction = match app.packet_sort_direction {
                    PacketSortDirection::Desc => PacketSortDirection::Asc,
                    PacketSortDirection::Asc => PacketSortDirection::Desc,
                };
            } else {
                app.packet_sort_column = PacketSortColumn::Timestamp;
                app.packet_sort_direction = PacketSortDirection::Desc; // Newest first by default
            }
            app.packet_scroll_offset = 0;
        }
        Char('2') => {
            // Sort by Direction
            if app.packet_sort_column == PacketSortColumn::Direction {
                app.packet_sort_direction = match app.packet_sort_direction {
                    PacketSortDirection::Desc => PacketSortDirection::Asc,
                    PacketSortDirection::Asc => PacketSortDirection::Desc,
                };
            } else {
                app.packet_sort_column = PacketSortColumn::Direction;
                app.packet_sort_direction = PacketSortDirection::Asc;
            }
            app.packet_scroll_offset = 0;
        }
        Char('3') => {
            if app.packet_sort_column == PacketSortColumn::Protocol {
                app.packet_sort_direction = if app.packet_sort_direction == PacketSortDirection::Asc {
                    PacketSortDirection::Desc
                } else {
                    PacketSortDirection::Asc
                };
            } else {
                app.packet_sort_column = PacketSortColumn::Protocol;
                app.packet_sort_direction = PacketSortDirection::Asc;
            }
        }
        Char('4') => {
            if app.packet_sort_column == PacketSortColumn::SourceIp {
                app.packet_sort_direction = if app.packet_sort_direction == PacketSortDirection::Asc {
                    PacketSortDirection::Desc
                } else {
                    PacketSortDirection::Asc
                };
            } else {
                app.packet_sort_column = PacketSortColumn::SourceIp;
                app.packet_sort_direction = PacketSortDirection::Asc;
            }
        }
        Char('5') => {
            if app.packet_sort_column == PacketSortColumn::SourcePort {
                app.packet_sort_direction = if app.packet_sort_direction == PacketSortDirection::Asc {
                    PacketSortDirection::Desc
                } else {
                    PacketSortDirection::Asc
                };
            } else {
                app.packet_sort_column = PacketSortColumn::SourcePort;
                app.packet_sort_direction = PacketSortDirection::Asc;
            }
        }
        Char('6') => {
            if app.packet_sort_column == PacketSortColumn::DestIp {
                app.packet_sort_direction = if app.packet_sort_direction == PacketSortDirection::Asc {
                    PacketSortDirection::Desc
                } else {
                    PacketSortDirection::Asc
                };
            } else {
                app.packet_sort_column = PacketSortColumn::DestIp;
                app.packet_sort_direction = PacketSortDirection::Asc;
            }
        }
        Char('7') => {
            if app.packet_sort_column == PacketSortColumn::DestPort {
                app.packet_sort_direction = if app.packet_sort_direction == PacketSortDirection::Asc {
                    PacketSortDirection::Desc
                } else {
                    PacketSortDirection::Asc
                };
            } else {
                app.packet_sort_column = PacketSortColumn::DestPort;
                app.packet_sort_direction = PacketSortDirection::Asc;
            }
        }
        KeyCode::Char('8') => {
            if app.packet_sort_column == PacketSortColumn::Size {
                app.packet_sort_direction = if app.packet_sort_direction == PacketSortDirection::Asc {
                    PacketSortDirection::Desc
                } else {
                    PacketSortDirection::Asc
                };
            } else {
                app.packet_sort_column = PacketSortColumn::Size;
                app.packet_sort_direction = PacketSortDirection::Asc;
            }
        }
        Char('e') => {
            // Export filtered packets to CSV
            if let Some(pid) = app.selected_process {
                // Clone the process info to avoid borrowing conflicts
                if let Some(process_info) = app.stats.get(&pid).cloned() {
                    if let Err(e) = crate::ui::renderers::packet_details::export_packets_to_csv(app, &process_info, pid) {
                        // Set error notification instead of using eprintln
                        app.export_notification_state = crate::types::NotificationState::Active(format!("❌ Export failed: {}", e));
                        app.export_notification_time = Some(std::time::Instant::now());
                        eprintln!("Export error: {}", e);
                    }
                }
            }
        }
        _ => {}
    }
    false
} 