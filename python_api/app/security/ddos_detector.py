# src/security/ddos_detector.py
from typing import List, Dict, Optional, Set, Deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import ipaddress # For IP address validation if needed

@dataclass
class DDoSAlert:
    attack_type: str  # 'volumetric', 'protocol', 'application'
    target_ip: Optional[str] # Can be None if target is unclear
    source_ips: List[str]
    attack_vectors: List[str] # e.g. ['syn_flood', 'high_bandwidth']
    peak_rate: float # e.g. packets/sec or bytes/sec depending on attack_type
    baseline_rate: float
    amplification_factor: float # peak_rate / baseline_rate
    duration_seconds: float
    confidence: float # 0.0 to 1.0
    severity: str # 'low', 'medium', 'high', 'critical'
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, any] = field(default_factory=dict)


@dataclass
class SourceIPStats:
    bytes_sent: int = 0
    packets_sent: int = 0
    connection_count: int = 0
    target_ips: Set[str] = field(default_factory=set)
    incomplete_connections: int = 0 # e.g. SYN sent, no SYN-ACK or RST
    amplification_attempts: int = 0 # e.g. DNS query to known open resolver
    udp_flood_score: int = 0 # Heuristic score for UDP flood characteristics
    icmp_flood_score: int = 0 # Heuristic score for ICMP flood
    syn_packets: int = 0 # Count of SYN packets from this source

@dataclass
class SourceIPSummary: # Used for summarizing top sources
    ip: str
    stats: SourceIPStats

    @property
    def bytes_sent_prop(self): # Property to allow sorting
        return self.stats.bytes_sent
    
    @property
    def packets_sent_prop(self):
        return self.stats.packets_sent

    @property
    def syn_packets_prop(self):
        return self.stats.syn_packets


class DDoSDetector:
    def __init__(self):
        # Configuration
        self.baseline_window_duration = timedelta(minutes=30)
        self.detection_window_duration = timedelta(minutes=1) # Shorter window for faster detection
        
        # Volumetric thresholds
        self.volumetric_bandwidth_multiplier = 10.0 # e.g. 10x baseline bandwidth
        self.volumetric_packet_rate_multiplier = 10.0 # e.g. 10x baseline packet rate
        
        # Protocol attack thresholds
        self.syn_flood_pps_threshold = 500  # SYN packets per second to a target/overall
        self.udp_amplification_attempt_threshold = 5 # attempts from a source
        self.icmp_flood_pps_threshold = 300 # ICMP packets per second

        # Application attack thresholds (example for HTTP)
        self.http_flood_rps_threshold = 200 # requests per second to a target

        # Historical data for baseline calculation (stores rates per detection_window_duration)
        self.bandwidth_history: Deque[float] = deque(maxlen=int(self.baseline_window_duration / self.detection_window_duration))
        self.packet_rate_history: Deque[float] = deque(maxlen=int(self.baseline_window_duration / self.detection_window_duration))
        self.connection_rate_history: Deque[float] = deque(maxlen=int(self.baseline_window_duration / self.detection_window_duration)) # New connections
        self.http_request_rate_history: Deque[float] = deque(maxlen=int(self.baseline_window_duration / self.detection_window_duration))


        # Current window tracking
        self.current_window_start_time = datetime.utcnow()
        self.current_window_flows: List[Dict] = []
        self.current_window_bandwidth_bytes = 0
        self.current_window_packets = 0
        self.current_window_new_connections = 0 # Track new SYN packets or initial flow establishments
        self.current_window_http_requests = 0

        # Per-source IP tracking for the current window
        self.current_window_source_ip_stats: Dict[str, SourceIPStats] = defaultdict(SourceIPStats)
        # Per-target IP tracking for SYN floods in current window
        self.current_window_target_syn_counts: Dict[str, int] = defaultdict(int)


    def analyze_traffic_and_bandwidth(self, flows: List[Dict], overall_bandwidth_stats: Dict) -> List[DDoSAlert]:
        """
        Analyze current traffic flows and overall bandwidth statistics for DDoS patterns.
        `overall_bandwidth_stats` should contain keys like 'total_bytes_per_sec', 'total_packets_per_sec'.
        """
        alerts: List[DDoSAlert] = []
        current_time = datetime.utcnow()

        # Accumulate data for the current detection window
        self.current_window_flows.extend(flows)
        self.current_window_bandwidth_bytes += overall_bandwidth_stats.get('total_bytes_this_window', 0) # Assuming this is passed
        self.current_window_packets += overall_bandwidth_stats.get('total_packets_this_window', 0) # Assuming this is passed

        for flow in flows:
            self._analyze_single_flow_for_stats(flow)

        # If detection window has passed, perform analysis
        if current_time >= self.current_window_start_time + self.detection_window_duration:
            window_duration_secs = (current_time - self.current_window_start_time).total_seconds()
            if window_duration_secs == 0: window_duration_secs = 1.0 # Avoid division by zero

            # Calculate rates for the completed window
            current_bandwidth_bps = (self.current_window_bandwidth_bytes * 8) / window_duration_secs
            current_packet_pps = self.current_window_packets / window_duration_secs
            current_connection_cps = self.current_window_new_connections / window_duration_secs
            current_http_rps = self.current_window_http_requests / window_duration_secs
            
            # Volumetric Attack Detection
            alerts.extend(self._detect_volumetric_attacks(current_bandwidth_bps, current_packet_pps, current_time))
            
            # Protocol Attack Detection
            alerts.extend(self._detect_protocol_attacks(current_connection_cps, current_time))

            # Application Attack Detection (e.g. HTTP flood)
            alerts.extend(self._detect_application_attacks(current_http_rps, current_time))

            # Update baselines with the rates from the completed window
            self.bandwidth_history.append(current_bandwidth_bps)
            self.packet_rate_history.append(current_packet_pps)
            self.connection_rate_history.append(current_connection_cps)
            self.http_request_rate_history.append(current_http_rps)
            
            # Reset current window trackers
            self.current_window_start_time = current_time
            self.current_window_flows = []
            self.current_window_bandwidth_bytes = 0
            self.current_window_packets = 0
            self.current_window_new_connections = 0
            self.current_window_http_requests = 0
            self.current_window_source_ip_stats.clear()
            self.current_window_target_syn_counts.clear()
            
        return alerts

    def _analyze_single_flow_for_stats(self, flow: Dict):
        try:
            src_ip = str(flow['src_ip'])
            dst_ip = str(flow['dst_ip'])
            protocol = int(flow['protocol'])
            bytes_sent = int(flow.get('bytes_sent', 0))
            packets_sent = int(flow.get('packets_sent', 0))
            connection_state = str(flow.get('connection_state', 'unknown')).lower()
            dst_port = int(flow.get('dst_port', 0))

            source_stats = self.current_window_source_ip_stats[src_ip]
            source_stats.bytes_sent += bytes_sent
            source_stats.packets_sent += packets_sent
            source_stats.connection_count += 1
            source_stats.target_ips.add(dst_ip)

            if protocol == 6: # TCP
                if connection_state in ['syn_sent', 'synsent']: # SYN from source
                    source_stats.syn_packets += 1
                    self.current_window_target_syn_counts[dst_ip] += 1
                    if source_stats.connection_count == 1 : # First packet of a flow from this source
                         self.current_window_new_connections +=1
                if dst_port in [80, 443, 8080, 8443]: # Basic HTTP/S request tracking
                    self.current_window_http_requests += 1


            elif protocol == 17: # UDP
                # Check for common amplification ports (DNS, NTP, SNMP, SSDP, Memcached)
                amplification_ports = {53, 123, 161, 1900, 11211, 389, 137} 
                if dst_port in amplification_ports:
                    source_stats.amplification_attempts += 1
            
            elif protocol == 1: # ICMP
                source_stats.icmp_flood_score += packets_sent # Simple score based on packet count

        except (KeyError, ValueError) as e:
            print(f"Skipping flow in DDoS analysis due to data issue: {e}, flow: {flow}")


    def _detect_volumetric_attacks(self, current_bandwidth_bps: float, current_packet_pps: float, current_time: datetime) -> List[DDoSAlert]:
        alerts = []
        baseline_bw = self._calculate_median_baseline(self.bandwidth_history)
        baseline_pps = self._calculate_median_baseline(self.packet_rate_history)
        
        duration_secs = self.detection_window_duration.total_seconds()

        if baseline_bw > 0 and current_bandwidth_bps > baseline_bw * self.volumetric_bandwidth_multiplier:
            top_sources = self._get_top_sources_by_bytes()
            primary_target = self._identify_primary_target(top_sources)
            alerts.append(DDoSAlert(
                attack_type='volumetric', target_ip=primary_target,
                source_ips=[s.ip for s in top_sources[:10]], attack_vectors=['bandwidth_flood'],
                peak_rate=current_bandwidth_bps, baseline_rate=baseline_bw,
                amplification_factor=current_bandwidth_bps / baseline_bw,
                duration_seconds=duration_secs, confidence=0.8, severity='high', timestamp=current_time,
                details={"description": f"Bandwidth {current_bandwidth_bps/1e6:.2f} Mbps exceeded baseline {baseline_bw/1e6:.2f} Mbps"}
            ))

        if baseline_pps > 0 and current_packet_pps > baseline_pps * self.volumetric_packet_rate_multiplier:
            top_sources = self._get_top_sources_by_packets()
            primary_target = self._identify_primary_target(top_sources)
            alerts.append(DDoSAlert(
                attack_type='volumetric', target_ip=primary_target,
                source_ips=[s.ip for s in top_sources[:10]], attack_vectors=['packet_rate_flood'],
                peak_rate=current_packet_pps, baseline_rate=baseline_pps,
                amplification_factor=current_packet_pps / baseline_pps,
                duration_seconds=duration_secs, confidence=0.8, severity='high', timestamp=current_time,
                details={"description": f"Packet rate {current_packet_pps:.0f} pps exceeded baseline {baseline_pps:.0f} pps"}
            ))
        return alerts

    def _detect_protocol_attacks(self, current_connection_cps: float, current_time: datetime) -> List[DDoSAlert]:
        alerts = []
        duration_secs = self.detection_window_duration.total_seconds()

        # SYN Flood Detection (overall and per target)
        overall_syn_pps = sum(s.syn_packets for s in self.current_window_source_ip_stats.values()) / duration_secs
        if overall_syn_pps > self.syn_flood_pps_threshold:
            top_syn_sources = self._get_top_sources_by_syn_packets()
            primary_target = self._identify_primary_target_from_syn_counts()
            alerts.append(DDoSAlert(
                attack_type='protocol', target_ip=primary_target,
                source_ips=[s.ip for s in top_syn_sources[:10]], attack_vectors=['syn_flood'],
                peak_rate=overall_syn_pps, baseline_rate=self._calculate_median_baseline(self.connection_rate_history),
                amplification_factor=overall_syn_pps / max(1, self._calculate_median_baseline(self.connection_rate_history)),
                duration_seconds=duration_secs, confidence=0.9, severity='high', timestamp=current_time,
                details={"description": f"Overall SYN PPS {overall_syn_pps:.0f} exceeded threshold {self.syn_flood_pps_threshold}"}
            ))
        
        # UDP Amplification (based on attempts to known ports)
        amplification_sources = [
            s.ip for s_ip, s in self.current_window_source_ip_stats.items() 
            if s.amplification_attempts > self.udp_amplification_attempt_threshold
        ]
        if len(amplification_sources) > 0: # If any source exceeds threshold
             alerts.append(DDoSAlert(
                attack_type='protocol', target_ip=None, # Target might be varied for amplification
                source_ips=amplification_sources[:10], attack_vectors=['udp_amplification_attempt'],
                peak_rate=float(len(amplification_sources)), baseline_rate=0, # No real baseline for "attempts"
                amplification_factor=float('inf'), duration_seconds=duration_secs,
                confidence=0.7, severity='medium', timestamp=current_time,
                details={"description": f"{len(amplification_sources)} source(s) attempting UDP amplification."}
            ))
        return alerts

    def _detect_application_attacks(self, current_http_rps: float, current_time: datetime) -> List[DDoSAlert]:
        alerts = []
        baseline_http_rps = self._calculate_median_baseline(self.http_request_rate_history)
        duration_secs = self.detection_window_duration.total_seconds()

        if baseline_http_rps > 0 and current_http_rps > baseline_http_rps * self.volumetric_bandwidth_multiplier : # Re-use volumetric multiplier for now
            # Identify primary target from HTTP flows (most frequent dst_ip on port 80/443)
            http_target_counts = defaultdict(int)
            for flow in self.current_window_flows:
                if flow.get('protocol') == 6 and flow.get('dst_port') in [80, 443, 8080, 8443]:
                    http_target_counts[str(flow['dst_ip'])] +=1
            
            primary_http_target = max(http_target_counts, key=http_target_counts.get) if http_target_counts else None
            top_sources = self._get_top_sources_by_packets() # Or a more specific app-layer metric

            alerts.append(DDoSAlert(
                attack_type='application', target_ip=primary_http_target,
                source_ips=[s.ip for s in top_sources[:10]], attack_vectors=['http_flood'],
                peak_rate=current_http_rps, baseline_rate=baseline_http_rps,
                amplification_factor=current_http_rps / baseline_http_rps,
                duration_seconds=duration_secs, confidence=0.75, severity='medium', timestamp=current_time,
                details={"description": f"HTTP RPS {current_http_rps:.0f} exceeded baseline {baseline_http_rps:.0f}"}
            ))
        return alerts

    def _calculate_median_baseline(self, history: Deque[float]) -> float:
        if not history: return 1.0 # Avoid division by zero, assume a minimal baseline
        return statistics.median(history) if len(history) > len(history.maxlen)//2 else sum(history)/len(history) # Median if enough data, else avg

    def _get_top_sources_by_bytes(self) -> List[SourceIPSummary]:
        return sorted(
            [SourceIPSummary(ip, stats) for ip, stats in self.current_window_source_ip_stats.items()],
            key=lambda x: x.bytes_sent_prop, reverse=True
        )

    def _get_top_sources_by_packets(self) -> List[SourceIPSummary]:
        return sorted(
            [SourceIPSummary(ip, stats) for ip, stats in self.current_window_source_ip_stats.items()],
            key=lambda x: x.packets_sent_prop, reverse=True
        )
    
    def _get_top_sources_by_syn_packets(self) -> List[SourceIPSummary]:
        return sorted(
            [SourceIPSummary(ip, stats) for ip, stats in self.current_window_source_ip_stats.items() if stats.syn_packets > 0],
            key=lambda x: x.syn_packets_prop, reverse=True
        )

    def _identify_primary_target(self, top_sources: List[SourceIPSummary]) -> Optional[str]:
        if not top_sources: return None
        # Heuristic: most common target among top sources
        target_counts = defaultdict(int)
        for summary in top_sources[:5]: # Look at top 5 sources
            for target_ip in summary.stats.target_ips:
                target_counts[target_ip] += 1
        return max(target_counts, key=target_counts.get) if target_counts else None
    
    def _identify_primary_target_from_syn_counts(self) -> Optional[str]:
        if not self.current_window_target_syn_counts: return None
        return max(self.current_window_target_syn_counts, key=self.current_window_target_syn_counts.get)


# Example Usage (for testing)
if __name__ == '__main__':
    detector = DDoSDetector()
    # Simulate receiving flow data and bandwidth stats over time
    import time
    for i in range(int(detector.baseline_window_duration.total_seconds() / detector.detection_window_duration.total_seconds()) + 5) :
        # Simulate some normal traffic
        sim_flows = [
            {'src_ip': f'10.0.0.{j}', 'dst_ip': '203.0.113.1', 'protocol': 6, 'bytes_sent': 1000, 'packets_sent': 10, 'connection_state': 'established', 'dst_port': 80}
            for j in range(5)
        ]
        sim_bw_stats = {'total_bytes_this_window': 5000 * 20, 'total_packets_this_window': 50 * 20} # 20x per sec
        
        if i > 35 : # Simulate an attack
             print(f"Simulating attack at iteration {i}")
             sim_flows.extend([
                {'src_ip': f'1.2.3.{j}', 'dst_ip': '192.168.1.100', 'protocol': 6, 'bytes_sent': 10000, 'packets_sent': 100, 'connection_state': 'syn_sent', 'dst_port': 80}
                for j in range(50) # 50 attacking sources
             ])
             sim_bw_stats['total_bytes_this_window'] += 50 * 10000 * 20 # 20x per sec
             sim_bw_stats['total_packets_this_window'] += 50 * 100 * 20 # 20x per sec


        alerts = detector.analyze_traffic_and_bandwidth(sim_flows, sim_bw_stats)
        if alerts:
            print(f"[{detector.current_window_start_time}] Detected {len(alerts)} DDoS alerts:")
            for alert_obj in alerts:
                print(f"  {alert_obj.attack_type} against {alert_obj.target_ip}, Severity: {alert_obj.severity}, Peak: {alert_obj.peak_rate:.2f}, Baseline: {alert_obj.baseline_rate:.2f}")
        
        # Simulate passage of detection window duration
        detector.current_window_start_time -= detector.detection_window_duration # Force window to seem passed for next iteration
        # time.sleep(detector.detection_window_duration.total_seconds()) # In real scenario
    print("DDoS detection simulation finished.")