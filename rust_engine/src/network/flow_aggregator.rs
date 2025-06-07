// src/network/flow_aggregator.rs
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tokio::time::{interval, Interval};
use serde::Serialize; 
use tracing; 

use super::flow::{NetworkFlow, PacketDirection}; 

pub struct FlowAggregator {
    flows: HashMap<FlowKey, NetworkFlow>,
    flow_timeout: Duration,
    
    top_talkers_by_bytes: Vec<TopTalker>,
    top_talkers_by_packets: Vec<TopTalker>,
    protocol_distribution: HashMap<u8, ProtocolStats>,
    
    cleanup_timer: Interval,
    aggregation_timer: Interval,
    security_awareness: SecurityAwareFlowMetrics,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopTalker {
    pub ip: IpAddr,
    pub bytes_total: u64,
    pub packets_total: u64,
    pub flows_count: u32,
    pub protocols: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityMetrics {
    pub is_ddos_attempt: bool,
    pub port_scan_detected: bool,
    pub suspicious_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerformanceMetrics {
    pub average_latency_ms: f32,
    pub jitter_ms: f32,
    pub packet_loss_percentage: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthCorrelation {
    pub health_score: f32, // 0.0 (bad) to 1.0 (good)
    pub status_message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityAwareFlowMetrics {
    pub suspicious_activity_indicators: SecurityMetrics,
    pub performance_impact_of_attacks: PerformanceMetrics,
    pub network_health_correlation: HealthCorrelation,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolStats {
    pub protocol: u8,
    pub flows_count: u32,
    pub bytes_total: u64,
    pub packets_total: u64,
    pub percentage_of_total_flows: f64, 
    pub percentage_of_total_bytes: f64, 
}

#[derive(Debug, Serialize)]
pub struct FlowSummary {
    pub timestamp: SystemTime,
    pub total_flows_in_window: u32, 
    pub active_flows_count: u32, 
    pub top_talkers_bytes: Vec<TopTalker>,
    pub top_talkers_packets: Vec<TopTalker>,
    pub protocol_distribution: Vec<ProtocolStats>,
    pub bandwidth_usage: BandwidthStats,
    pub security_awareness: SecurityAwareFlowMetrics,
}

#[derive(Debug, Serialize)]
pub struct BandwidthStats {
    pub total_bytes_per_sec: f64,
    pub total_packets_per_sec: f64,
    pub peak_bandwidth_in_window: f64, 
    pub average_bandwidth_in_window: f64, 
}

impl FlowAggregator {
    pub fn new(flow_timeout_secs: u64, aggregation_window_secs: u64, cleanup_interval_secs: u64) -> Self {
        Self {
            flows: HashMap::new(),
            flow_timeout: Duration::from_secs(flow_timeout_secs),
            top_talkers_by_bytes: Vec::new(),
            top_talkers_by_packets: Vec::new(),
            protocol_distribution: HashMap::new(),
            cleanup_timer: interval(Duration::from_secs(cleanup_interval_secs)),
            aggregation_timer: interval(Duration::from_secs(aggregation_window_secs)),
            security_awareness: SecurityAwareFlowMetrics {
                suspicious_activity_indicators: SecurityMetrics {
                    is_ddos_attempt: false,
                    port_scan_detected: false,
                    suspicious_ips: vec![],
                },
                performance_impact_of_attacks: PerformanceMetrics {
                    average_latency_ms: 0.0,
                    jitter_ms: 0.0,
                    packet_loss_percentage: 0.0,
                },
                network_health_correlation: HealthCorrelation {
                    health_score: 1.0,
                    status_message: "Network health is optimal.".to_string(),
                },
            },
        }
    }
    
    pub fn flows_count(&self) -> usize {
        self.flows.len()
    }
    
    pub async fn process_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        packet_size: u16,
        tcp_flags: Option<u8>,
    ) {
        let flow_key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };
        
        // Determine direction before mutable borrow of self.flows
        let direction = self.determine_packet_direction(src_ip, dst_ip);
        
        let flow = self.flows.entry(flow_key.clone()).or_insert_with(|| {
            NetworkFlow::new(src_ip, dst_ip, src_port, dst_port, protocol)
        });
        
        flow.update_with_packet(packet_size, direction, tcp_flags);
    }
    
    pub async fn tick_cleanup(&mut self) {
        self.cleanup_timer.tick().await;
        self.cleanup_expired_flows();
    }
    
    pub async fn tick_aggregation(&mut self) {
        self.aggregation_timer.tick().await;
        self.update_aggregation_stats().await;
    }
    
    pub fn cleanup_expired_flows(&mut self) {
        let now = SystemTime::now();
        let timeout = self.flow_timeout;
        
        self.flows.retain(|_, flow| {
            if let Ok(age) = now.duration_since(flow.last_seen) {
                age < timeout
            } else {
                true
            }
        });
        
        tracing::debug!("Flow cleanup complete. Active flows: {}", self.flows.len());
    }
    
    async fn update_aggregation_stats(&mut self) {
        self.calculate_top_talkers();
        self.calculate_protocol_distribution();
        
        let summary = self.generate_flow_summary();
        if let Err(e) = self.send_to_backend(&summary).await {
            tracing::error!("Failed to send flow summary to backend: {}", e);
        }
        tracing::debug!("Aggregation stats updated and sent. Active flows: {}", self.flows.len());
    }
    
    pub fn calculate_top_talkers(&mut self) {
        let mut talker_stats: HashMap<IpAddr, (u64, u64, u32, Vec<u8>)> = HashMap::new(); 
        
        for flow in self.flows.values() {
            let src_entry = talker_stats.entry(flow.src_ip).or_insert((0, 0, 0, Vec::new()));
            src_entry.0 += flow.bytes_sent;
            src_entry.1 += flow.packets_sent;
            src_entry.2 += 1;
            if !src_entry.3.contains(&flow.protocol) {
                src_entry.3.push(flow.protocol);
            }
            
            let dst_entry = talker_stats.entry(flow.dst_ip).or_insert((0, 0, 0, Vec::new()));
            dst_entry.0 += flow.bytes_received;
            dst_entry.1 += flow.packets_received;
            dst_entry.2 += 1; 
            if !dst_entry.3.contains(&flow.protocol) {
                dst_entry.3.push(flow.protocol);
            }
        }
        
        let mut talkers: Vec<TopTalker> = talker_stats.into_iter().map(|(ip, (bytes, packets, flows_count, protocols))| {
            TopTalker { ip, bytes_total: bytes, packets_total: packets, flows_count, protocols }
        }).collect();
        
        talkers.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));
        self.top_talkers_by_bytes = talkers.iter().take(10).cloned().collect();
        
        talkers.sort_by(|a, b| b.packets_total.cmp(&a.packets_total));
        self.top_talkers_by_packets = talkers.iter().take(10).cloned().collect();
    }
    
    pub fn calculate_protocol_distribution(&mut self) {
        let mut current_protocol_stats: HashMap<u8, (u32, u64, u64)> = HashMap::new(); 
        let mut grand_total_flows = 0u32;
        let mut grand_total_bytes = 0u64;
        
        for flow in self.flows.values() {
            let stats = current_protocol_stats.entry(flow.protocol).or_insert((0, 0, 0));
            stats.0 += 1; 
            stats.1 += flow.bytes_sent + flow.bytes_received; 
            stats.2 += flow.packets_sent + flow.packets_received; 
            
            grand_total_flows += 1;
            grand_total_bytes += flow.bytes_sent + flow.bytes_received;
        }
        
        self.protocol_distribution.clear();
        for (protocol, (flows, bytes, packets)) in current_protocol_stats {
            let perc_flows = if grand_total_flows > 0 { (flows as f64 / grand_total_flows as f64) * 100.0 } else { 0.0 };
            let perc_bytes = if grand_total_bytes > 0 { (bytes as f64 / grand_total_bytes as f64) * 100.0 } else { 0.0 };
            self.protocol_distribution.insert(protocol, ProtocolStats {
                protocol,
                flows_count: flows,
                bytes_total: bytes,
                packets_total: packets,
                percentage_of_total_flows: perc_flows,
                percentage_of_total_bytes: perc_bytes,
            });
        }
    }
    
    pub fn generate_flow_summary(&self) -> FlowSummary {
        let active_flows_count = self.flows.len() as u32;
        let total_flows_in_window = active_flows_count; 
        let bandwidth_stats = self.calculate_bandwidth_stats_for_summary();
        
        FlowSummary {
            timestamp: SystemTime::now(),
            total_flows_in_window,
            active_flows_count,
            top_talkers_bytes: self.top_talkers_by_bytes.clone(),
            top_talkers_packets: self.top_talkers_by_packets.clone(),
            protocol_distribution: self.protocol_distribution.values().cloned().collect(),
            bandwidth_usage: bandwidth_stats,
            security_awareness: self.security_awareness.clone(),
        }
    }
    
    fn calculate_bandwidth_stats_for_summary(&self) -> BandwidthStats {
        let mut total_bytes_per_sec_sum = 0.0;
        let mut total_packets_per_sec_sum = 0.0;
        let mut peak_bps_in_window = 0.0;
        let num_flows = self.flows.len();

        if num_flows == 0 {
            return BandwidthStats {
                total_bytes_per_sec: 0.0,
                total_packets_per_sec: 0.0,
                peak_bandwidth_in_window: 0.0,
                average_bandwidth_in_window: 0.0,
            };
        }
        
        for flow in self.flows.values() {
            total_bytes_per_sec_sum += flow.bytes_per_second;
            total_packets_per_sec_sum += flow.packets_per_second;
            if flow.bytes_per_second > peak_bps_in_window {
                peak_bps_in_window = flow.bytes_per_second;
            }
        }
        
        BandwidthStats {
            total_bytes_per_sec: total_bytes_per_sec_sum,
            total_packets_per_sec: total_packets_per_sec_sum,
            peak_bandwidth_in_window: peak_bps_in_window,
            average_bandwidth_in_window: total_bytes_per_sec_sum / num_flows as f64,
        }
    }
    
    pub async fn send_to_backend(&self, summary: &FlowSummary) -> Result<(), redis::RedisError> {
        let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
        let client = redis::Client::open(redis_url)?;
        let mut con = client.get_multiplexed_async_connection().await?; 
        
        let serialized = serde_json::to_string(summary).map_err(|e| 
            redis::RedisError::from(std::io::Error::new(std::io::ErrorKind::Other, e))
        )?;
        
        redis::cmd("PUBLISH")
            .arg("network_flows")
            .arg(serialized)
            .query_async::<_, ()>(&mut con) 
            .await?;
        Ok(())
    }
    
    fn determine_packet_direction(&self, src_ip: IpAddr, dst_ip: IpAddr) -> PacketDirection {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                if src.is_private() && !dst.is_private() {
                    PacketDirection::Outbound
                } else if !src.is_private() && dst.is_private() {
                    PacketDirection::Inbound
                } else if src.is_private() && dst.is_private() {
                    PacketDirection::Outbound
                } else { 
                    PacketDirection::Outbound 
                }
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let src_is_local_scope = src.is_loopback() ||
                                         (src.segments()[0] & 0xfe00 == 0xfc00) || 
                                         (src.segments()[0] & 0xffc0 == 0xfe80);  
                let dst_is_local_scope = dst.is_loopback() ||
                                         (dst.segments()[0] & 0xfe00 == 0xfc00) || 
                                         (dst.segments()[0] & 0xffc0 == 0xfe80);  

                if src_is_local_scope && !dst_is_local_scope {
                    PacketDirection::Outbound 
                } else if !src_is_local_scope && dst_is_local_scope {
                    PacketDirection::Inbound  
                } else { 
                    PacketDirection::Outbound 
                }
            }
            _ => PacketDirection::Outbound,
        }
    }
}