use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use ratatui::style::Color;

// Process cleanup configuration
pub const PROCESS_CLEANUP_INTERVAL_SECS: u64 = 5; // Check for dead processes every 5 seconds

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
    pub user_name: Option<String>,
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
    pub user_name: Option<String>,
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
            user_name: info.user_name.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ProcessIdentifier {
    pub pid: i32,
    pub name: String,
    pub container_name: Option<String>,
    pub user_name: Option<String>,
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
    Sent,        // Total sent bytes
    SentRate,    // Sent bytes per second
    Received,    // Total received bytes
    ReceivedRate, // Received bytes per second
    Container,
    User,
}

#[derive(PartialEq, Clone, Copy)]
pub enum AppMode {
    Normal,
    EditingAlert,
    SystemOverview,
}

pub enum EditingField {
    Threshold,
    Command,
}

#[derive(PartialEq, Clone, Copy)]
pub enum MetricsMode {
    Combined,    // Send + Receive (current behavior)
    SendOnly,    // Only sent bandwidth
    ReceiveOnly, // Only received bandwidth
}

#[derive(PartialEq, Clone, Copy)]
pub enum ChartType {
    ProcessLines,    // Line chart for individual process
    SystemStacked,   // Stacked area chart for all processes
}

pub struct App {
    pub start_time: Instant,
    pub stats: HashMap<i32, ProcessInfo>,
    pub sort_by: SortColumn,
    pub sort_direction: SortDirection,
    pub containers_mode: bool,
    pub show_total_columns: bool,
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
    pub last_alert_message_time: Option<Instant>, // Track when the alert message was set
    pub dead_processes_cache: HashSet<i32>, // Cache of known dead processes to avoid re-checking
    pub command_execution_log: Vec<(Instant, String)>, // Timestamped execution log
    pub bandwidth_mode: bool,
    pub system_bandwidth_history: Vec<(f64, Vec<(i32, f64, f64)>)>, // (timestamp, [(pid, sent_rate, received_rate)])
    pub chart_type: ChartType,
    pub chart_datasets: Vec<(String, Vec<(f64, f64)>, ratatui::style::Color)>,
    pub process_colors: HashMap<String, Color>,
    pub metrics_mode: MetricsMode,
    // System Overview Dashboard fields
    pub system_stats: SystemStats,
    pub system_stats_prev: SystemStats,
    pub total_quota_threshold: u64,
    pub threshold_exceeded: bool,
    pub threshold_exceeded_time: Option<Instant>,
    pub system_alerts: HashSet<i32>, // PIDs with system alerts that should blink
    pub alert_scroll_offset: usize, // Scroll offset for alert progress bars
    // Performance optimization
    pub last_chart_update: Instant, // Last time chart datasets were updated
    pub last_cleanup_time: Option<Instant>, // Last time processes were cleaned up
}

impl App {
    pub fn new(containers_mode: bool, show_total_columns: bool) -> Self {
        App {
            start_time: Instant::now(),
            stats: HashMap::new(),
            sort_by: SortColumn::Pid,
            sort_direction: SortDirection::Asc,
            containers_mode,
            show_total_columns,
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
            last_alert_message_time: None, // Track when the alert message was set
            dead_processes_cache: HashSet::new(), // Cache of known dead processes to avoid re-checking
            command_execution_log: Vec::new(),
            bandwidth_mode: false,
            system_bandwidth_history: Vec::new(),
            chart_type: ChartType::ProcessLines,
            chart_datasets: Vec::new(),
            process_colors: HashMap::new(),
            metrics_mode: MetricsMode::Combined,
            // System Overview Dashboard fields
            system_stats: SystemStats::new(),
            system_stats_prev: SystemStats::new(),
            total_quota_threshold: 1024 * 1024 * 1024, // Default 1 GB total quota
            threshold_exceeded: false,
            threshold_exceeded_time: None,
            system_alerts: HashSet::new(),
            alert_scroll_offset: 0,
            // Performance optimization
            last_chart_update: Instant::now(),
            last_cleanup_time: None,
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
            SortColumn::SentRate => sorted.sort_by_key(|(_, info)| info.sent_rate),
            SortColumn::Received => sorted.sort_by_key(|(_, info)| info.received),
            SortColumn::ReceivedRate => sorted.sort_by_key(|(_, info)| info.received_rate),
            SortColumn::Container => sorted.sort_by_key(|(_, info)| &info.container_name),
            SortColumn::User => sorted.sort_by_key(|(_, info)| &info.user_name),
        }

        if self.sort_direction == SortDirection::Desc {
            sorted.reverse();
        }

        sorted
    }

    pub fn update_system_stats(&mut self) {
        // Store previous stats for rate calculation
        self.system_stats_prev = self.system_stats.clone();
        
        // Reset current stats
        self.system_stats = SystemStats::new();
        
        // Aggregate protocol statistics from all processes
        for (_, process_info) in &self.stats {
            // For now, we'll estimate protocol breakdown (this should be collected from packet capture)
            // TCP is typically the majority of traffic, UDP is less, ICMP minimal
            let total_rate = process_info.sent_rate + process_info.received_rate;
            
            // Rough estimation - in real implementation this would come from packet analysis
            self.system_stats.tcp_rate += (total_rate as f64 * 0.8) as u64;
            self.system_stats.udp_rate += (total_rate as f64 * 0.15) as u64;
            self.system_stats.icmp_rate += (total_rate as f64 * 0.01) as u64;
            self.system_stats.other_rate += (total_rate as f64 * 0.04) as u64;
            
            let total_bytes = process_info.sent + process_info.received;
            self.system_stats.tcp_bytes += (total_bytes as f64 * 0.8) as u64;
            self.system_stats.udp_bytes += (total_bytes as f64 * 0.15) as u64;
            self.system_stats.icmp_bytes += (total_bytes as f64 * 0.01) as u64;
            self.system_stats.other_bytes += (total_bytes as f64 * 0.04) as u64;
            
            // Estimate packet counts (rough average packet sizes)
            // TCP: ~1400 bytes, UDP: ~512 bytes, ICMP: ~64 bytes, Other: ~800 bytes
            self.system_stats.tcp_packets += (total_bytes as f64 * 0.8 / 1400.0) as u64;
            self.system_stats.udp_packets += (total_bytes as f64 * 0.15 / 512.0) as u64;
            self.system_stats.icmp_packets += (total_bytes as f64 * 0.01 / 64.0) as u64;
            self.system_stats.other_packets += (total_bytes as f64 * 0.04 / 800.0) as u64;
        }
        
        // Check if quota threshold is exceeded and update system alerts
        let total_bytes = self.system_stats.total_bytes();
        if total_bytes > self.total_quota_threshold {
            if !self.threshold_exceeded {
                self.threshold_exceeded = true;
                self.threshold_exceeded_time = Some(std::time::Instant::now());
            }
            
            // Check for system alerts that should trigger
            for (pid, alert) in &self.alerts {
                if let AlertAction::SystemAlert = alert.action {
                    if let Some(process_info) = self.stats.get(pid) {
                        let process_bytes = process_info.sent + process_info.received;
                        if process_bytes > alert.threshold_bytes {
                            self.system_alerts.insert(*pid);
                        }
                    }
                }
            }
        } else {
            // Reset threshold exceeded state if we're below 80% of quota
            if total_bytes <= (self.total_quota_threshold as f64 * 0.8) as u64 {
                self.threshold_exceeded = false;
                self.threshold_exceeded_time = None;
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AlertAction {
    Kill,
    CustomCommand(String),
    SystemAlert, // New system-wide alert that just blinks/highlights
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Alert {
    pub process_pid: i32,
    pub threshold_bytes: u64,
    pub action: AlertAction,
}

#[derive(Clone)]
pub struct SystemStats {
    pub tcp_bytes: u64,
    pub tcp_rate: u64,
    pub tcp_packets: u64,
    pub udp_bytes: u64,
    pub udp_rate: u64,
    pub udp_packets: u64,
    pub icmp_bytes: u64,
    pub icmp_rate: u64,
    pub icmp_packets: u64,
    pub other_bytes: u64,
    pub other_rate: u64,
    pub other_packets: u64,
}

impl SystemStats {
    pub fn new() -> Self {
        SystemStats {
            tcp_bytes: 0,
            tcp_rate: 0,
            tcp_packets: 0,
            udp_bytes: 0,
            udp_rate: 0,
            udp_packets: 0,
            icmp_bytes: 0,
            icmp_rate: 0,
            icmp_packets: 0,
            other_bytes: 0,
            other_rate: 0,
            other_packets: 0,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.tcp_bytes + self.udp_bytes + self.icmp_bytes + self.other_bytes
    }
}