use crossterm::event::KeyCode;
use crate::types::{Alert, AlertAction, App, AppMode, SortColumn, SortDirection, EditingField, ChartType, MetricsMode};
use crate::ui::utils::{parse_input_to_bytes, format_bytes};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

/// Handle keyboard input events for all application modes
pub fn handle_key_event(app: &mut App, key: KeyCode) -> bool {
    match app.mode {
        AppMode::EditingAlert => handle_alert_editing_keys(app, key),
        AppMode::Normal => handle_normal_mode_keys(app, key),
        AppMode::SystemOverview => handle_overview_mode_keys(app, key),
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
    let mut num_actions = 2; // Kill, Edit
    if let Some(pid) = app.selected_process {
        if app.alerts.contains_key(&pid) {
            num_actions = 3; // Add Remove option
        }
    }

    match key {
        KeyCode::Esc => {
            app.show_action_panel = false;
            app.selected_action = 0;
        }
        KeyCode::Up => {
            if app.selected_action > 0 {
                app.selected_action -= 1;
            }
        }
        KeyCode::Down => {
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
                    2 if has_alert => "Remove",
                    _ => "",
                };

                match action_str {
                    "Kill" => {
                        if signal::kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
                            app.stats.remove(&pid);
                            app.alerts.remove(&pid);
                            app.killed_processes.insert(pid);
                            app.selected_process = None;
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
        KeyCode::Char('p') => app.sort_by = SortColumn::Pid,
        KeyCode::Char('n') => app.sort_by = SortColumn::Name,
        KeyCode::Char('s') => app.sort_by = SortColumn::Sent,
        KeyCode::Char('r') => app.sort_by = SortColumn::Received,
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
            // Cycle through modes: Main -> Bandwidth -> Overview -> Main
            if app.mode == AppMode::SystemOverview {
                // Currently in overview mode, go back to normal
                app.mode = AppMode::Normal;
            } else if app.bandwidth_mode {
                // Currently in bandwidth mode, go to overview
                app.mode = AppMode::SystemOverview;
                app.bandwidth_mode = false;
            } else if app.mode == AppMode::Normal {
                // Currently in normal mode, go to bandwidth
                app.bandwidth_mode = true;
            }
        }
        KeyCode::Char('t') => {
            // Toggle chart type only when in bandwidth mode
            if app.bandwidth_mode {
                app.chart_type = match app.chart_type {
                    ChartType::ProcessLines => ChartType::SystemStacked,
                    ChartType::SystemStacked => ChartType::ProcessLines,
                };
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
            // Cycle from SystemOverview to Main mode
            app.mode = AppMode::Normal;
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
        _ => {}
    }
    false
} 