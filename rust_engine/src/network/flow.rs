// src/network/flow.rs
// use std::collections::HashMap; // Unused
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    // Basic flow identifiers
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // TCP=6, UDP=17, ICMP=1
    
    // Flow statistics
    pub start_time: SystemTime,
    pub last_seen: SystemTime,
    pub duration: Duration,
    
    // Traffic metrics
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    
    // Advanced metrics for security analysis
    pub packet_sizes: Vec<u16>,
    pub inter_arrival_times: Vec<Duration>,
    pub tcp_flags: Vec<u8>, // For TCP flows
    pub connection_state: ConnectionState,
    
    // Derived metrics
    pub avg_packet_size: f64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynReceived,
    FinWait,
    Closed,
    Reset,
    Unknown,
}

// Define PacketDirection here as it's used in update_with_packet
#[derive(Debug, Clone)]
pub enum PacketDirection {
    Outbound,
    Inbound,
}

impl NetworkFlow {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        let now = SystemTime::now();
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            start_time: now,
            last_seen: now,
            duration: Duration::from_secs(0),
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packet_sizes: Vec::new(),
            inter_arrival_times: Vec::new(),
            tcp_flags: Vec::new(),
            connection_state: ConnectionState::Unknown,
            avg_packet_size: 0.0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
        }
    }
    
    pub fn update_with_packet(&mut self, packet_size: u16, direction: PacketDirection, tcp_flags_option: Option<u8>) {
        let now = SystemTime::now();
        
        if self.packets_sent > 0 || self.packets_received > 0 { 
            if let Ok(elapsed) = now.duration_since(self.last_seen) {
                self.inter_arrival_times.push(elapsed);
            }
        }
        self.last_seen = now;
        if let Ok(duration) = now.duration_since(self.start_time) {
            self.duration = duration;
        }
        
        match direction {
            PacketDirection::Outbound => {
                self.packets_sent += 1;
                self.bytes_sent += packet_size as u64;
            },
            PacketDirection::Inbound => {
                self.packets_received += 1;
                self.bytes_received += packet_size as u64;
            }
        }
        
        self.packet_sizes.push(packet_size);
        if let Some(flags) = tcp_flags_option {
            if self.protocol == 6 { 
                self.tcp_flags.push(flags);
                self.update_connection_state(flags);
            }
        }
        
        self.calculate_derived_metrics();
    }
    
    fn calculate_derived_metrics(&mut self) {
        let total_packets = self.packets_sent + self.packets_received;
        let total_bytes = self.bytes_sent + self.bytes_received;
        
        if total_packets > 0 {
            self.avg_packet_size = total_bytes as f64 / total_packets as f64;
        } else {
            self.avg_packet_size = 0.0;
        }
        
        let duration_secs = self.duration.as_secs_f64();
        if duration_secs > 0.0 {
            self.packets_per_second = total_packets as f64 / duration_secs;
            self.bytes_per_second = total_bytes as f64 / duration_secs;
        } else {
            self.packets_per_second = 0.0;
            self.bytes_per_second = 0.0;
        }
    }
    
    fn update_connection_state(&mut self, tcp_flags: u8) {
        if self.protocol != 6 {
            self.connection_state = ConnectionState::Unknown;
            return;
        }

        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        const FIN: u8 = 0x01;
        const RST: u8 = 0x04;
        
        match self.connection_state {
            ConnectionState::Unknown | ConnectionState::Closed | ConnectionState::Reset => {
                if tcp_flags & SYN != 0 && tcp_flags & ACK == 0 {
                    self.connection_state = ConnectionState::SynSent;
                }
            }
            ConnectionState::SynSent => {
                if tcp_flags & SYN != 0 && tcp_flags & ACK != 0 {
                    self.connection_state = ConnectionState::SynReceived;
                } else if tcp_flags & ACK != 0 { 
                     self.connection_state = ConnectionState::Established;
                }
            }
            ConnectionState::SynReceived => {
                if tcp_flags & ACK != 0 && tcp_flags & SYN == 0 { 
                    self.connection_state = ConnectionState::Established;
                }
            }
            ConnectionState::Established => {
                if tcp_flags & FIN != 0 {
                    self.connection_state = ConnectionState::FinWait;
                } else if tcp_flags & RST != 0 {
                    self.connection_state = ConnectionState::Reset;
                }
            }
            ConnectionState::FinWait => {
                if tcp_flags & ACK != 0 { 
                    if tcp_flags & RST != 0 {
                        self.connection_state = ConnectionState::Reset;
                    }
                } else if tcp_flags & FIN != 0 {
                } else if tcp_flags & RST != 0 {
                    self.connection_state = ConnectionState::Reset;
                }
            }
            // Removed unreachable _ => {} as all variants are covered or fall through
        }

        if tcp_flags & RST != 0 {
            self.connection_state = ConnectionState::Reset;
        }
    }
}