use crate::types::Connection;

pub fn connection_from_packet(packet_data: &[u8]) -> Option<Connection> {
    use etherparse::{SlicedPacket, InternetSlice, TransportSlice};

    // Try Ethernet first (for regular interfaces)
    let sliced = if let Ok(sliced) = SlicedPacket::from_ethernet(packet_data) {
        sliced
    } else {
        // For "any" interface, try IP directly
        SlicedPacket::from_ip(packet_data).ok()?
    };

    let Some(net) = sliced.net else { return None };

    let (source_ip, dest_ip, protocol) = match net {
        InternetSlice::Ipv4(ipv4) => (
            ipv4.header().source_addr().into(),
            ipv4.header().destination_addr().into(),
            ipv4.header().protocol(),
        ),
        InternetSlice::Ipv6(ipv6) => (
            ipv6.header().source_addr().into(),
            ipv6.header().destination_addr().into(),
            ipv6.header().next_header(),
        ),
    };

    let Some(transport) = sliced.transport else { return None };

    let (source_port, dest_port) = match transport {
        TransportSlice::Tcp(tcp) => (tcp.source_port(), tcp.destination_port()),
        TransportSlice::Udp(udp) => (udp.source_port(), udp.destination_port()),
        _ => return None,
    };

    Some(Connection {
        source_port,
        dest_port,
        source_ip,
        dest_ip,
        protocol: protocol.into(),
    })
} 