use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;
use log::LevelFilter;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH}; // Removed Duration
use redis::AsyncCommands; // For async Redis commands

// Declare network module
mod network;

// Import FlowAggregator
use crate::network::flow_aggregator::FlowAggregator;

// const METRICS_PUBLISH_INTERVAL_SECS: u64 = 5; // For the old system, will be commented out
const DEVICE_PUBLISH_INTERVAL_SECS: u64 = 10; // Less frequent for devices
const FLOW_TIMEOUT_SECS: u64 = 60 * 5; // 5 minutes for flow timeout (used by FlowAggregator)
const FLOW_AGGREGATION_WINDOW_SECS: u64 = 5; // How often FlowAggregator publishes FlowSummary
const FLOW_AGGREGATOR_CLEANUP_INTERVAL_SECS: u64 = 60; // How often FlowAggregator cleans its internal state

// const NETWORK_METRICS_CHANNEL: &str = "network_metrics_channel"; // For the old system
const DEVICE_DISCOVERY_CHANNEL: &str = "device_discovery_channel";

#[derive(Debug, Clone, Serialize)]
struct PublishedDiscoveredDevice {
    ip_addr: String,
    mac_addr: String,
    last_seen: u64,
    timestamp: u64,
}

#[derive(Debug, Clone)]
struct DiscoveredDevice {
    ip_addr: Ipv4Addr,
    mac_addr: MacAddr,
    last_seen: u64,
}

type DeviceCache = Arc<Mutex<HashMap<MacAddr, DiscoveredDevice>>>;

async fn get_redis_connection() -> redis::RedisResult<redis::aio::MultiplexedConnection> {
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let client = redis::Client::open(redis_url)?;
    client.get_multiplexed_async_connection().await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .filter_module("rust_engine", LevelFilter::Trace)
        .init();

    // Interface selection logic (remains the same)
    let interface_name = env::args().nth(1).unwrap_or_else(|| {
        log::warn!("No interface name provided, attempting to find a default.");
        let interfaces = datalink::interfaces();
        let default_interface = interfaces
            .into_iter()
            .find(|iface: &NetworkInterface| {
                iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty()
            })
            .map(|iface| iface.name);

        match default_interface {
            Some(name) => {
                log::info!("Using default interface: {}", name);
                name
            }
            None => {
                log::error!("No suitable default interface found. Please specify one.");
                std::process::exit(1);
            }
        }
    });

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .clone()
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .ok_or_else(|| format!("Interface {} not found", interface_name))?;

    log::info!("Starting packet capture on interface: {}", interface.name);

    // Create an MPSC channel for passing packet data from capture thread to processing task
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1000);

    let interface_name_for_loop = interface.name.clone();

    // Spawn a dedicated thread for the blocking packet capture
    std::thread::spawn(move || {
        let (_, mut pnet_rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => {
                log::error!("Failed to create datalink channel: {}", e);
                return;
            }
        };
        
        loop {
            match pnet_rx.next() {
                Ok(packet) => {
                    if tx.blocking_send(packet.to_vec()).is_err() {
                        log::error!("Failed to send packet to processing task. Channel closed.");
                        break;
                    }
                }
                Err(e) => {
                    log::error!("An error occurred while reading from interface: {}", e);
                    break;
                }
            }
        }
    });

    let device_cache: DeviceCache = Arc::new(Mutex::new(HashMap::new()));
    let flow_aggregator_arc = Arc::new(Mutex::new(FlowAggregator::new(
        FLOW_TIMEOUT_SECS,
        FLOW_AGGREGATION_WINDOW_SECS,
        FLOW_AGGREGATOR_CLEANUP_INTERVAL_SECS,
    )));

    // Create separate timer tasks
    let cleanup_aggregator = flow_aggregator_arc.clone();
    let cleanup_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(FLOW_AGGREGATOR_CLEANUP_INTERVAL_SECS)).await;
            let mut agg = cleanup_aggregator.lock().await;
            agg.cleanup_expired_flows();
            log::debug!("Cleanup tick completed");
        }
    });

    let aggregation_aggregator = flow_aggregator_arc.clone();
    let aggregation_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(FLOW_AGGREGATION_WINDOW_SECS)).await;
            let mut agg = aggregation_aggregator.lock().await;
            agg.calculate_top_talkers();
            agg.calculate_protocol_distribution();
            
            let summary = agg.generate_flow_summary();
            if let Err(e) = agg.send_to_backend(&summary).await {
                log::error!("Failed to send flow summary to backend: {}", e);
            } else {
                log::info!("FlowSummary published to Redis. Active flows: {}", agg.flows_count());
            }
        }
    });

    // Main async processing loop
    loop {
        tokio::select! {
            Some(packet_data) = rx.recv() => {
                if let Some(ethernet_packet) = EthernetPacket::new(&packet_data) {
                    handle_ethernet_packet(&interface_name_for_loop, &ethernet_packet, device_cache.clone(), flow_aggregator_arc.clone()).await;
                } else {
                    log::warn!("Malformed Ethernet packet received via channel.");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("Ctrl-C received, shutting down.");
                cleanup_task.abort();
                aggregation_task.abort();
                break;
            }
        }
    }

    Ok(())
}

async fn handle_ethernet_packet(
    interface_name: &str,
    ethernet: &EthernetPacket<'_>, // Added lifetime
    device_cache: DeviceCache,
    flow_aggregator_arc: Arc<Mutex<FlowAggregator>>,
) {
    let packet_length = ethernet.packet().len() as u16; 

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                let protocol_type = ipv4_packet.get_next_level_protocol();
                let protocol_u8 = protocol_type.0; 
                let src_ip = IpAddr::V4(ipv4_packet.get_source());
                let dst_ip = IpAddr::V4(ipv4_packet.get_destination());
                let mut tcp_flags: Option<u8> = None;

                let (src_port, dst_port) = match protocol_type {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv4_packet.payload()) {
                            tcp_flags = Some(tcp.get_flags());
                            (tcp.get_source(), tcp.get_destination())
                        } else { (0,0) }
                    }
                    IpNextHeaderProtocols::Udp => {
                        UdpPacket::new(ipv4_packet.payload()).map_or((0,0), |p| (p.get_source(), p.get_destination()))
                    }
                    _ => (0,0) 
                };

                // Process all packets with identified protocols, not just those with non-zero ports
                if protocol_type == IpNextHeaderProtocols::Tcp || protocol_type == IpNextHeaderProtocols::Udp {
                    let mut agg = flow_aggregator_arc.lock().await;
                    agg.process_packet(src_ip, dst_ip, src_port, dst_port, protocol_u8, packet_length, tcp_flags).await;
                    log::debug!(
                        "[{}] Processed packet: {} -> {} | Proto: {} | Ports: {}:{} | Len: {} bytes",
                        interface_name, src_ip, dst_ip, protocol_u8, src_port, dst_port, packet_length
                    );
                }
                 log::trace!(
                    "[{}] IPv4 | {} -> {} | Proto: {:?} | Len: {} bytes",
                    interface_name, src_ip, dst_ip, protocol_type, packet_length
                );
            }
        }
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(ethernet.payload()) {
                let sender_mac = arp_packet.get_sender_hw_addr();
                let sender_ip = arp_packet.get_sender_proto_addr();

                if sender_mac != MacAddr::zero() && sender_ip != Ipv4Addr::new(0,0,0,0) {
                    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    let device_info = DiscoveredDevice {
                        ip_addr: sender_ip,
                        mac_addr: sender_mac,
                        last_seen: current_time,
                    };

                    let mut cache = device_cache.lock().await;
                    let mut publish_update = true;

                    if let Some(existing_device) = cache.get(&sender_mac) {
                        if current_time.saturating_sub(existing_device.last_seen) < DEVICE_PUBLISH_INTERVAL_SECS {
                            publish_update = false;
                        }
                    }
                    
                    cache.insert(sender_mac, device_info.clone());

                    if publish_update {
                        log::info!(
                            "[{}] ARP: Discovered/Updated Device - MAC: {}, IP: {}. Publishing to Redis.",
                            interface_name, sender_mac, sender_ip
                        );
                        let published_device = PublishedDiscoveredDevice {
                            ip_addr: device_info.ip_addr.to_string(),
                            mac_addr: device_info.mac_addr.to_string(),
                            last_seen: device_info.last_seen,
                            timestamp: current_time,
                        };
                        match get_redis_connection().await {
                            Ok(mut conn) => {
                                match serde_json::to_string(&published_device) {
                                    Ok(json_payload) => {
                                        let _: () = match conn.publish::<&str, String, i32>(DEVICE_DISCOVERY_CHANNEL, json_payload).await {
                                            Ok(_) => log::debug!("Published device {} to Redis.", sender_mac),
                                            Err(e) => log::error!("Failed to publish device to Redis: {}", e),
                                        };
                                    }
                                    Err(e) => log::error!("Failed to serialize device: {}", e),
                                }
                            }
                            Err(e) => log::error!("Failed to get Redis connection for device: {}", e),
                        }
                    } else {
                         log::trace!("[{}] ARP: Device {} already recently published or updated.", interface_name, sender_mac);
                    }
                } else {
                     log::debug!(
                        "[{}] ARP Packet ignored (zero MAC/IP): Sender MAC: {}, Sender IP: {}",
                        interface_name, sender_mac, sender_ip
                    );
                }
            } else {
                log::warn!("[{}] Malformed ARP Packet", interface_name);
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6_packet) = Ipv6Packet::new(ethernet.payload()) {
                let protocol_type = ipv6_packet.get_next_header();
                let protocol_u8 = protocol_type.0; 
                let src_ip = IpAddr::V6(ipv6_packet.get_source());
                let dst_ip = IpAddr::V6(ipv6_packet.get_destination());
                let mut tcp_flags: Option<u8> = None;

                let (src_port, dst_port) = match protocol_type {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv6_packet.payload()) {
                            tcp_flags = Some(tcp.get_flags());
                            (tcp.get_source(), tcp.get_destination())
                        } else { (0,0) }
                    }
                    IpNextHeaderProtocols::Udp => {
                        UdpPacket::new(ipv6_packet.payload()).map_or((0,0), |p| (p.get_source(), p.get_destination()))
                    }
                     _ => (0,0)
                };

                // Process all packets with identified protocols, not just those with non-zero ports
                if protocol_type == IpNextHeaderProtocols::Tcp || protocol_type == IpNextHeaderProtocols::Udp {
                    let mut agg = flow_aggregator_arc.lock().await;
                    agg.process_packet(src_ip, dst_ip, src_port, dst_port, protocol_u8, packet_length, tcp_flags).await;
                    log::debug!(
                        "[{}] Processed IPv6 packet: {} -> {} | Proto: {} | Ports: {}:{} | Len: {} bytes",
                        interface_name, src_ip, dst_ip, protocol_u8, src_port, dst_port, packet_length
                    );
                }
                log::trace!(
                    "[{}] IPv6 | {} -> {} | Proto: {:?} | Len: {} bytes",
                    interface_name, src_ip, dst_ip, protocol_type, packet_length
                );
            }
        }
        _ => {
            log::trace!(
                "[{}] Unknown/Unsupported EtherType: {:?}; Length: {}",
                interface_name,
                ethernet.get_ethertype(),
                ethernet.payload().len()
            );
        }
    }
}