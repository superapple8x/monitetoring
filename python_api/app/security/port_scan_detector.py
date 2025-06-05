# src/security/port_scan_detector.py
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress

@dataclass
class ConnectionAttempt:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: int # From the flow data
    connection_state: str # From the flow data
    scan_indicators: List[str] = field(default_factory=list)

@dataclass
class PortScanAlert:
    source_ip: str
    target_ip: str
    scanned_ports: List[int]
    scan_duration_seconds: float
    scan_type: str  # 'tcp_syn', 'tcp_connect', 'udp', 'mixed', 'port_sweep'
    confidence: float
    severity: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


class PortScanDetector:
    def __init__(self):
        # Configuration thresholds
        self.tcp_syn_threshold = 20  # ports in time window for a single target
        self.tcp_connect_threshold = 15 # Not explicitly used in provided logic, but good to have
        self.udp_threshold = 25 # ports in time window for a single target
        self.time_window = timedelta(minutes=5)
        self.sweep_threshold = 10  # different IPs scanned on the same port by a source
        self.min_attempts_for_scan = 5 # Min attempts to consider a scan on a single target

        # Tracking data structures
        # Stores attempts from a source IP: Dict[src_ip_str, List[ConnectionAttempt]]
        self.connection_attempts: Dict[str, List[ConnectionAttempt]] = defaultdict(list)
        # Stores target IPs scanned by a source IP: Dict[src_ip_str, Set[dst_ip_str]]
        self.port_sweep_target_tracking: Dict[str, Set[str]] = defaultdict(set)

    def analyze_flows(self, flows: List[Dict]) -> List[PortScanAlert]:
        """Analyze network flows for port scan patterns"""
        alerts = []
        current_time = datetime.utcnow()

        for flow in flows:
            self._process_flow(flow, current_time)

        alerts.extend(self._detect_target_port_scans(current_time))
        alerts.extend(self._detect_port_sweeps(current_time))
        
        self._cleanup_old_data(current_time)
        return alerts

    def _process_flow(self, flow: Dict, current_time: datetime):
        """Process a single flow and record potential scan attempts."""
        try:
            src_ip = str(flow['src_ip'])
            dst_ip = str(flow['dst_ip'])
            dst_port = int(flow['dst_port'])
            protocol = int(flow['protocol'])
            # Ensure 'duration' is timedelta; if it's float/int (seconds), convert
            duration_val = flow.get('duration', 0.0)
            if isinstance(duration_val, (int, float)):
                duration = timedelta(seconds=duration_val)
            elif isinstance(duration_val, dict) and "secs" in duration_val : # Handle dict like {'secs': S, 'nanos': N}
                 duration = timedelta(seconds=duration_val.get("secs",0), microseconds=duration_val.get("nanos",0)//1000)
            else: # Assuming it's already timedelta or can be defaulted
                duration = duration_val if isinstance(duration_val, timedelta) else timedelta(seconds=0)

            connection_state = str(flow.get('connection_state', 'unknown')).lower()
        except (KeyError, ValueError) as e:
            # Log error or handle missing/malformed flow data
            print(f"Skipping flow due to missing/malformed data: {e}, flow: {flow}")
            return

        scan_indicators = self._identify_scan_indicators(protocol, connection_state, duration, dst_port)

        if scan_indicators:
            attempt = ConnectionAttempt(
                timestamp=current_time, # Or use flow's timestamp if available and recent
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                connection_state=connection_state,
                scan_indicators=scan_indicators
            )
            self.connection_attempts[src_ip].append(attempt)
            self.port_sweep_target_tracking[src_ip].add(dst_ip)

    def _identify_scan_indicators(self, protocol: int, connection_state: str, duration: timedelta, dst_port: int) -> List[str]:
        indicators = []
        if protocol == 6:  # TCP
            # SYN scan often results in SYN_SENT from scanner, or RST from target if port closed
            if connection_state in ['syn_sent', 'reset', 'synsent', 'synreceived']: # 'synreceived' if scanner spoofs and gets SYN-ACK
                indicators.append('tcp_syn_indicator')
            if duration < timedelta(seconds=2) and connection_state != 'established': # Rapid, non-established
                indicators.append('rapid_tcp_attempt')
        elif protocol == 17:  # UDP
            # UDP scans often get no reply (packets_received might be 0 for the flow from scanner's perspective)
            # or ICMP port unreachable. This needs flow-level 'packets_received' or ICMP correlation.
            # For now, a simple indicator if it's UDP.
            indicators.append('udp_indicator')
        
        if dst_port in self._get_common_scan_ports():
            indicators.append('common_scan_port')
        if dst_port > 1024 and dst_port < 49152: # Registered ports, often scanned
             pass # Could add 'registered_port_scan'
        elif dst_port >= 49152: # Dynamic/private ports
            indicators.append('high_port_scan')
        return indicators

    def _detect_target_port_scans(self, current_time: datetime) -> List[PortScanAlert]:
        """Detects scans where one source probes multiple ports on one target."""
        alerts = []
        for src_ip, attempts in list(self.connection_attempts.items()): # Iterate over a copy
            recent_attempts = [
                att for att in attempts if current_time - att.timestamp <= self.time_window
            ]
            if not recent_attempts:
                continue

            target_groups = defaultdict(list)
            for attempt in recent_attempts:
                target_groups[attempt.dst_ip].append(attempt)

            for target_ip, target_specific_attempts in target_groups.items():
                if len(target_specific_attempts) < self.min_attempts_for_scan:
                    continue
                
                alert = self._analyze_scan_on_target(src_ip, target_ip, target_specific_attempts, current_time)
                if alert:
                    alerts.append(alert)
        return alerts

    def _analyze_scan_on_target(self, src_ip: str, target_ip: str, attempts: List[ConnectionAttempt], current_time: datetime) -> Optional[PortScanAlert]:
        scanned_ports_set = set()
        tcp_syn_indicators_count = 0
        udp_indicators_count = 0
        
        min_time = current_time
        max_time = attempts[0].timestamp if attempts else current_time

        for attempt in attempts:
            scanned_ports_set.add(attempt.dst_port)
            if 'tcp_syn_indicator' in attempt.scan_indicators:
                tcp_syn_indicators_count += 1
            if 'udp_indicator' in attempt.scan_indicators:
                udp_indicators_count += 1
            if attempt.timestamp < min_time: min_time = attempt.timestamp
            if attempt.timestamp > max_time: max_time = attempt.timestamp
        
        scanned_ports_list = sorted(list(scanned_ports_set))
        num_distinct_ports = len(scanned_ports_list)
        scan_duration = (max_time - min_time).total_seconds()
        if scan_duration < 1.0: scan_duration = 1.0 # Avoid division by zero for very fast scans

        scan_type = "mixed"
        confidence = 0.0

        if tcp_syn_indicators_count >= self.tcp_syn_threshold and num_distinct_ports >= self.tcp_syn_threshold:
            scan_type = "tcp_syn"
            confidence = min(1.0, (tcp_syn_indicators_count / (self.tcp_syn_threshold * 1.5)) * 0.7 + (num_distinct_ports / (self.tcp_syn_threshold*1.5)) * 0.3)
        elif udp_indicators_count >= self.udp_threshold and num_distinct_ports >= self.udp_threshold :
            scan_type = "udp"
            confidence = min(1.0, (udp_indicators_count / (self.udp_threshold * 1.5)) * 0.7 + (num_distinct_ports / (self.udp_threshold*1.5)) * 0.3)
        elif num_distinct_ports >= (self.tcp_syn_threshold + self.udp_threshold) / 2 : # General threshold for mixed
            scan_type = "mixed"
            confidence = min(1.0, num_distinct_ports / float((self.tcp_syn_threshold + self.udp_threshold))) * 0.8

        if confidence > 0.5: # Only create alert if confidence is somewhat high
            severity = self._calculate_severity(num_distinct_ports, scan_type, target_ip)
            return PortScanAlert(
                source_ip=src_ip, target_ip=target_ip, scanned_ports=scanned_ports_list,
                scan_duration_seconds=scan_duration, scan_type=scan_type,
                confidence=round(confidence,2), severity=severity, timestamp=max_time
            )
        return None

    def _detect_port_sweeps(self, current_time: datetime) -> List[PortScanAlert]:
        """Detects horizontal port sweeps (one source, one port, multiple targets)."""
        alerts = []
        for src_ip, attempts in list(self.connection_attempts.items()):
            recent_attempts = [
                att for att in attempts if current_time - att.timestamp <= self.time_window
            ]
            if not recent_attempts:
                continue

            # Group by port, then count distinct target IPs for that port
            port_to_targets_map = defaultdict(set)
            min_timestamps_per_port = defaultdict(lambda: current_time)
            max_timestamps_per_port = defaultdict(lambda: datetime.min)

            for attempt in recent_attempts:
                port_to_targets_map[attempt.dst_port].add(attempt.dst_ip)
                if attempt.timestamp < min_timestamps_per_port[attempt.dst_port]:
                    min_timestamps_per_port[attempt.dst_port] = attempt.timestamp
                if attempt.timestamp > max_timestamps_per_port[attempt.dst_port]:
                    max_timestamps_per_port[attempt.dst_port] = attempt.timestamp
            
            for port, target_ips_set in port_to_targets_map.items():
                if len(target_ips_set) >= self.sweep_threshold:
                    scan_duration = (max_timestamps_per_port[port] - min_timestamps_per_port[port]).total_seconds()
                    if scan_duration < 1.0: scan_duration = 1.0
                    
                    confidence = min(1.0, len(target_ips_set) / (self.sweep_threshold * 1.5)) * 0.85
                    severity = self._calculate_severity(len(target_ips_set), "port_sweep", f"Multiple ({len(target_ips_set)})")

                    alerts.append(PortScanAlert(
                        source_ip=src_ip,
                        target_ip=f"Multiple ({len(target_ips_set)} IPs)",
                        scanned_ports=[port],
                        scan_duration_seconds=scan_duration,
                        scan_type='port_sweep',
                        confidence=round(confidence,2),
                        severity=severity,
                        timestamp=max_timestamps_per_port[port]
                    ))
        return alerts

    def _calculate_severity(self, count: int, scan_type: str, target_ip_str: str) -> str:
        is_internal_target = False
        if not target_ip_str.startswith("Multiple"):
            try:
                ip_obj = ipaddress.ip_address(target_ip_str)
                is_internal_target = ip_obj.is_private
            except ValueError:
                pass # Not a valid IP string, assume external or non-specific

        base_severity = 'low'
        if scan_type == 'port_sweep':
            if count > self.sweep_threshold * 2: base_severity = 'high'
            elif count > self.sweep_threshold * 1.5: base_severity = 'medium'
        else: # Target scan
            threshold_avg = (self.tcp_syn_threshold + self.udp_threshold) / 2.0
            if count > threshold_avg * 2: base_severity = 'high'
            elif count > threshold_avg * 1.2: base_severity = 'medium'

        if is_internal_target:
            if base_severity == 'medium': return 'high'
            if base_severity == 'low': return 'medium'
        
        if scan_type == 'tcp_syn' and count > 200 : return 'critical' # Very broad SYN scan
        return base_severity

    def _get_common_scan_ports(self) -> Set[int]:
        return {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 137,138, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5432, 5800, 5900, 8000, 8080, 8443
        }

    def _cleanup_old_data(self, current_time: datetime):
        cutoff = current_time - self.time_window - timedelta(minutes=1) # Keep a bit longer than window
        for src_ip in list(self.connection_attempts.keys()):
            self.connection_attempts[src_ip] = [
                attempt for attempt in self.connection_attempts[src_ip] if attempt.timestamp > cutoff
            ]
            if not self.connection_attempts[src_ip]:
                del self.connection_attempts[src_ip]
                self.port_sweep_target_tracking.pop(src_ip, None)

# Example usage (for testing purposes)
if __name__ == '__main__':
    detector = PortScanDetector()
    # Simulate some flows
    flows_example = [
        # TCP SYN Scan from 1.1.1.1 to 2.2.2.2
        {'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'dst_port': 22, 'protocol': 6, 'connection_state': 'syn_sent', 'duration': 0.1},
        {'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'dst_port': 23, 'protocol': 6, 'connection_state': 'syn_sent', 'duration': 0.1},
        {'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'dst_port': 80, 'protocol': 6, 'connection_state': 'reset', 'duration': 0.2},
        # ... (add up to tcp_syn_threshold for alert)
        # Port Sweep from 3.3.3.3 on port 445
        {'src_ip': '3.3.3.3', 'dst_ip': '4.4.4.1', 'dst_port': 445, 'protocol': 6, 'connection_state': 'syn_sent', 'duration': 0.1},
        {'src_ip': '3.3.3.3', 'dst_ip': '4.4.4.2', 'dst_port': 445, 'protocol': 6, 'connection_state': 'syn_sent', 'duration': 0.1},
        # ... (add up to sweep_threshold for alert)
    ]
    
    # Populate for scan
    for i in range(25):
        flows_example.append({'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'dst_port': 1000+i, 'protocol': 6, 'connection_state': 'syn_sent', 'duration': 0.1, 'timestamp': datetime.utcnow()})

    # Populate for sweep
    for i in range(12):
        flows_example.append({'src_ip': '3.3.3.3', 'dst_ip': f'4.4.4.{i+1}', 'dst_port': 445, 'protocol': 6, 'connection_state': 'syn_sent', 'duration': 0.1, 'timestamp': datetime.utcnow()})


    alerts = detector.analyze_flows(flows_example)
    if alerts:
        print(f"Detected {len(alerts)} port scan alerts:")
        for alert_obj in alerts:
            print(f"  {alert_obj}")
    else:
        print("No port scan alerts detected.")