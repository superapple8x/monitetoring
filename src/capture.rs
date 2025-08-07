use crate::types::Connection;

pub fn connection_from_packet(packet_data: &[u8]) -> Option<Connection> {
    use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

    // NOTE [Linux -i any]: The "any" pseudo interface often uses Linux cooked
    // capture (SLL/SLL2). On some systems this can differ by kernel/version and
    // the pcap datalink. We currently try multiple parsers and heuristic
    // offsets. A more robust approach is to make parsing datalink-aware by
    // reading the datalink from the activated pcap handle and branching to the
    // correct parser/offsets accordingly, rather than guessing here.
    // For best reliability, prefer selecting a concrete interface (e.g., eth0).

    // Helper to build a Connection from a parsed SlicedPacket
    fn from_sliced(sliced: SlicedPacket<'_>) -> Option<Connection> {
        let net = sliced.net?;
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

        let transport = sliced.transport?;
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

    // Try common decoders first
    if let Ok(s) = SlicedPacket::from_ethernet(packet_data) {
        if let Some(conn) = from_sliced(s) { return Some(conn); }
    }
    if let Ok(s) = SlicedPacket::from_ip(packet_data) {
        if let Some(conn) = from_sliced(s) { return Some(conn); }
    }

    // Heuristic fallbacks for Linux cooked capture (SLL/SLL2)
    // SLL v1: 16-byte header; SLL v2: 20-byte header. After header, IP payload starts.
    // We attempt both offsets.
    if packet_data.len() > 16 {
        if let Ok(s) = SlicedPacket::from_ip(&packet_data[16..]) {
            if let Some(conn) = from_sliced(s) { return Some(conn); }
        }
    }
    if packet_data.len() > 20 {
        if let Ok(s) = SlicedPacket::from_ip(&packet_data[20..]) {
            if let Some(conn) = from_sliced(s) { return Some(conn); }
        }
    }

    None
}