use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH}; // Removed Duration
use redis::Commands; // For Redis commands

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


// Structs for the old metrics system (can be removed if fully deprecated)
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
struct PublishedFlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
}

#[derive(Debug, Clone, Serialize)]
struct PublishedFlowData {
    packet_count: u64,
    byte_count: u64,
    first_seen: u64,
    last_seen: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PublishedFlow {
    key: PublishedFlowKey,
    data: PublishedFlowData,
}

#[derive(Debug, Clone, Serialize, Default)]
struct PublishedInterfaceMetrics {
    timestamp: u64,
    interface_name: String,
    packets_in: u64,
    packets_out: u64,
    bytes_in: u64,
    bytes_out: u64,
    active_flows: Vec<PublishedFlow>,
}


#[derive(Debug, Clone, Serialize)]
struct PublishedDiscoveredDevice {
    ip_addr: String,
    mac_addr: String,
    last_seen: u64,
    timestamp: u64,
}

// Original structs for internal aggregation (used by old system)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: IpNextHeaderProtocol,
}

#[derive(Debug, Clone)]
struct FlowData {
    packet_count: u64,
    byte_count: u64,
    first_seen: u64,
    last_seen: u64,
}

#[derive(Debug, Clone, Default)]
struct InterfaceAggregatedMetrics {
    packets_in: u64,
    packets_out: u64,
    bytes_in: u64,
    bytes_out: u64,
    active_flows: HashMap<FlowKey, FlowData>,
}

#[derive(Debug, Clone)]
struct DiscoveredDevice {
    ip_addr: Ipv4Addr,
    mac_addr: MacAddr,
    last_seen: u64,
}

type DeviceCache = Arc<Mutex<HashMap<MacAddr, DiscoveredDevice>>>;
// type MetricCache = Arc<Mutex<InterfaceAggregatedMetrics>>; // Old system

fn get_redis_connection() -> redis::RedisResult<redis::Connection> {
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let client = redis::Client::open(redis_url)?;
    client.get_connection()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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
    log::info!("Available network interfaces:");
    for iface in interfaces.iter() {
        log::info!("  {}: UP: {}, Loopback: {}, MAC: {:?}, IPs: {:?}", 
                 iface.name, iface.is_up(), iface.is_loopback(), iface.mac, iface.ips);
    }

    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .ok_or_else(|| format!("Interface {} not found", interface_name))?;

    log::info!("Starting packet capture on interface: {}", interface.name);

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            log::error!("An error occurred when creating the datalink channel: {}", e);
            std::process::exit(1);
        }
    };

    let device_cache: DeviceCache = Arc::new(Mutex::new(HashMap::new()));

    // Instantiate FlowAggregator
    let flow_aggregator_arc = Arc::new(Mutex::new(FlowAggregator::new(
        FLOW_TIMEOUT_SECS,
        FLOW_AGGREGATION_WINDOW_SECS,
        FLOW_AGGREGATOR_CLEANUP_INTERVAL_SECS,
    )));

    // Periodic Metric Publisher Task (Old system - Commented out)
    /*
    // const METRICS_PUBLISH_INTERVAL_SECS: u64 = 5; // Defined above
    // const NETWORK_METRICS_CHANNEL: &str = "network_metrics_channel"; // Defined above
    // type MetricCache = Arc<Mutex<InterfaceAggregatedMetrics>>; // Defined above
    // let metric_cache: MetricCache = Arc::new(Mutex::new(InterfaceAggregatedMetrics::default()));
    // let interface_name_clone = interface.name.clone(); 
    // let metric_cache_publisher_clone = metric_cache.clone();
    // let if_name_for_metrics = interface_name_clone.clone();
    // tokio::spawn(async move {
    //     let mut interval = tokio::time::interval(std::time::Duration::from_secs(METRICS_PUBLISH_INTERVAL_SECS));
    //     loop {
    //         interval.tick().await;
    //         let mut metrics_guard = metric_cache_publisher_clone.lock().unwrap();
    //         let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    //         metrics_guard.active_flows.retain(|_, flow_data| {
    //             now.saturating_sub(flow_data.last_seen) < FLOW_TIMEOUT_SECS
    //         });

    //         let published_metrics = PublishedInterfaceMetrics {
    //             timestamp: now,
    //             interface_name: if_name_for_metrics.clone(),
    //             packets_in: metrics_guard.packets_in,
    //             packets_out: metrics_guard.packets_out,
    //             bytes_in: metrics_guard.bytes_in,
    //             bytes_out: metrics_guard.bytes_out,
    //             active_flows: metrics_guard.active_flows.iter().map(|(k, v)| PublishedFlow {
    //                 key: PublishedFlowKey {
    //                     src_ip: k.src_ip.to_string(),
    //                     dst_ip: k.dst_ip.to_string(),
    //                     src_port: k.src_port,
    //                     dst_port: k.dst_port,
    //                     protocol: format!("{:?}", k.protocol),
    //                 },
    //                 data: PublishedFlowData {
    //                     packet_count: v.packet_count,
    //                     byte_count: v.byte_count,
    //                     first_seen: v.first_seen,
    //                     last_seen: v.last_seen,
    //                 },
    //             }).collect(),
    //         };
            
    //         match get_redis_connection() {
    //             Ok(mut conn) => {
    //                 match serde_json::to_string(&published_metrics) {
    //                     Ok(json_payload) => {
    //                         match conn.publish::<&str, String, usize>(NETWORK_METRICS_CHANNEL, json_payload.clone()) {
    //                             Ok(_) => log::info!("Published metrics to Redis ({} flows).", published_metrics.active_flows.len()),
    //                             Err(e) => log::error!("Failed to publish metrics to Redis: {}", e),
    //                         };
    //                     }
    //                     Err(e) => log::error!("Failed to serialize metrics: {}", e),
    //                 }
    //             }
    //             Err(e) => log::error!("Failed to get Redis connection for metrics: {}", e),
    //         }
    //     }
    // });
    */

    loop {
        tokio::select! {
            packet_result = async { rx.next() } => {
                match packet_result {
                    Ok(packet_data) => {
                        if let Some(ethernet_packet) = EthernetPacket::new(packet_data) {
                             handle_ethernet_packet(&interface, &ethernet_packet, device_cache.clone(), flow_aggregator_arc.clone()).await;
                        } else {
                            log::warn!("Malformed Ethernet packet received.");
                        }
                    }
                    Err(e) => {
                        log::error!("An error occurred while reading: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("Ctrl-C received, shutting down.");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_ethernet_packet(
    interface: &NetworkInterface,
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

                if src_port != 0 && dst_port != 0 {
                    let mut agg = flow_aggregator_arc.lock().unwrap();
                    agg.process_packet(src_ip, dst_ip, src_port, dst_port, protocol_u8, packet_length, tcp_flags).await;
                }
                 log::trace!(
                    "[{}] IPv4 | {} -> {} | Proto: {:?} | Len: {} bytes",
                    interface.name, src_ip, dst_ip, protocol_type, packet_length
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

                    let mut cache = device_cache.lock().unwrap();
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
                            interface.name, sender_mac, sender_ip
                        );
                        let published_device = PublishedDiscoveredDevice {
                            ip_addr: device_info.ip_addr.to_string(),
                            mac_addr: device_info.mac_addr.to_string(),
                            last_seen: device_info.last_seen,
                            timestamp: current_time,
                        };
                        match get_redis_connection() {
                            Ok(mut conn) => {
                                match serde_json::to_string(&published_device) {
                                    Ok(json_payload) => {
                                        let _: () = match conn.publish::<&str, String, i32>(DEVICE_DISCOVERY_CHANNEL, json_payload) {
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
                         log::trace!("[{}] ARP: Device {} already recently published or updated.", interface.name, sender_mac);
                    }
                } else {
                     log::debug!(
                        "[{}] ARP Packet ignored (zero MAC/IP): Sender MAC: {}, Sender IP: {}",
                        interface.name, sender_mac, sender_ip
                    );
                }
            } else {
                log::warn!("[{}] Malformed ARP Packet", interface.name);
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

                if src_port != 0 && dst_port != 0 {
                    let mut agg = flow_aggregator_arc.lock().unwrap();
                    agg.process_packet(src_ip, dst_ip, src_port, dst_port, protocol_u8, packet_length, tcp_flags).await;
                }
                log::trace!(
                    "[{}] IPv6 | {} -> {} | Proto: {:?} | Len: {} bytes",
                    interface.name, src_ip, dst_ip, protocol_type, packet_length
                );
            }
        }
        _ => {
            log::trace!(
                "[{}] Unknown/Unsupported EtherType: {:?}; Length: {}",
                interface.name,
                ethernet.get_ethertype(),
                ethernet.payload().len()
            );
        }
    }
}