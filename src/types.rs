use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let bytes_f = bytes as f64;
    let unit_index = (bytes_f.log(THRESHOLD).floor() as usize).min(UNITS.len() - 1);
    let size = bytes_f / THRESHOLD.powi(unit_index as i32);
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct Connection {
    pub source_port: u16,
    pub dest_port: u16,
    pub source_ip: std::net::IpAddr,
    pub dest_ip: std::net::IpAddr,
    pub protocol: u8,
}

#[derive(Clone, Serialize)]
pub struct ProcessInfo {
    pub name: String,
    pub sent: u64,
    pub received: u64,
    pub sent_rate: u64,      // bytes per second
    pub received_rate: u64,  // bytes per second
    pub container_name: Option<String>,
    pub has_alert: bool,
    pub sent_history: Vec<(f64, f64)>,
    pub received_history: Vec<(f64, f64)>,
}

#[derive(Clone, Serialize)]
pub struct ProcessInfoFormatted {
    pub name: String,
    pub sent_bytes: u64,
    pub sent_formatted: String,
    pub sent_rate_bytes: u64,
    pub sent_rate_formatted: String,
    pub received_bytes: u64,
    pub received_formatted: String,
    pub received_rate_bytes: u64,
    pub received_rate_formatted: String,
    pub container_name: Option<String>,
}

impl From<&ProcessInfo> for ProcessInfoFormatted {
    fn from(info: &ProcessInfo) -> Self {
        ProcessInfoFormatted {
            name: info.name.clone(),
            sent_bytes: info.sent,
            sent_formatted: format_bytes(info.sent),
            sent_rate_bytes: info.sent_rate,
            sent_rate_formatted: format!("{}/s", format_bytes(info.sent_rate)),
            received_bytes: info.received,
            received_formatted: format_bytes(info.received),
            received_rate_bytes: info.received_rate,
            received_rate_formatted: format!("{}/s", format_bytes(info.received_rate)),
            container_name: info.container_name.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ProcessIdentifier {
    pub pid: i32,
    pub name: String,
    pub container_name: Option<String>,
}

#[derive(PartialEq)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(PartialEq)]
pub enum SortColumn {
    Pid,
    Name,
    Sent,
    Received,
    Container,
}

pub enum AppMode {
    Normal,
    EditingAlert,
}

pub enum EditingField {
    Threshold,
    Command,
}

pub struct App {
    pub start_time: Instant,
    pub stats: HashMap<i32, ProcessInfo>,
    pub sort_by: SortColumn,
    pub sort_direction: SortDirection,
    pub containers_mode: bool,
    pub alerts: HashMap<i32, Alert>,
    pub selected_process: Option<i32>,
    pub show_action_panel: bool,
    pub selected_action: usize,
    pub mode: AppMode,
    pub alert_input: String,
    pub command_input: String,
    pub selected_alert_action: usize,
    pub current_editing_field: EditingField,
    pub killed_processes: HashSet<i32>,
    pub alert_cooldowns: HashMap<i32, Instant>,
    pub last_alert_message: Option<String>,
    pub bandwidth_mode: bool,
}

impl App {
    pub fn new(containers_mode: bool) -> Self {
        App {
            start_time: Instant::now(),
            stats: HashMap::new(),
            sort_by: SortColumn::Pid,
            sort_direction: SortDirection::Asc,
            containers_mode,
            alerts: HashMap::new(),
            selected_process: None,
            show_action_panel: false,
            selected_action: 0,
            mode: AppMode::Normal,
            alert_input: String::new(),
            command_input: String::new(),
            selected_alert_action: 0,
            current_editing_field: EditingField::Threshold,
            killed_processes: HashSet::new(),
            alert_cooldowns: HashMap::new(),
            last_alert_message: None,
            bandwidth_mode: false,
        }
    }

    pub fn totals(&self) -> (u64, u64, u64, u64) {
        let mut total_sent = 0u64;
        let mut total_received = 0u64;
        let mut total_sent_rate = 0u64;
        let mut total_received_rate = 0u64;
        
        for info in self.stats.values() {
            total_sent += info.sent;
            total_received += info.received;
            total_sent_rate += info.sent_rate;
            total_received_rate += info.received_rate;
        }
        
        (total_sent, total_received, total_sent_rate, total_received_rate)
    }

    pub fn sorted_stats(&self) -> Vec<(&i32, &ProcessInfo)> {
        let mut sorted: Vec<_> = self.stats.iter().collect();
        match self.sort_by {
            SortColumn::Pid => sorted.sort_by_key(|(pid, _)| *pid),
            SortColumn::Name => sorted.sort_by_key(|(_, info)| &info.name),
            SortColumn::Sent => sorted.sort_by_key(|(_, info)| info.sent),
            SortColumn::Received => sorted.sort_by_key(|(_, info)| info.received),
            SortColumn::Container => sorted.sort_by_key(|(_, info)| &info.container_name),
        }

        if self.sort_direction == SortDirection::Desc {
            sorted.reverse();
        }
        sorted
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AlertAction {
    Kill,
    CustomCommand(String),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Alert {
    pub process_pid: i32,
    pub threshold_bytes: u64,
    pub action: AlertAction,
}