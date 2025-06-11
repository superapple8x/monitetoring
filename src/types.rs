use serde::Serialize;
use std::collections::HashMap;

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
    pub container_name: Option<String>,
}

#[derive(Clone)]
pub struct ProcessIdentifier {
    pub pid: i32,
    pub name: String,
    pub container_name: Option<String>,
}

pub enum SortColumn {
    Pid,
    Name,
    Sent,
    Received,
    Container,
}

pub struct App {
    pub stats: HashMap<i32, ProcessInfo>,
    pub sort_by: SortColumn,
    pub containers_mode: bool,
}

impl App {
    pub fn new(containers_mode: bool) -> Self {
        App {
            stats: HashMap::new(),
            sort_by: SortColumn::Pid,
            containers_mode,
        }
    }

    pub fn sorted_stats(&self) -> Vec<(&i32, &ProcessInfo)> {
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