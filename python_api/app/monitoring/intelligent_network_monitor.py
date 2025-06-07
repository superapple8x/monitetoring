from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import statistics
import logging
from collections import defaultdict, deque

# Import existing security components
from ..security.ddos_detector import DDoSDetector, DDoSAlert
from ..security.port_scan_detector import PortScanDetector
from ..security.ml_integration_manager import MLIntegrationManager

@dataclass
class NetworkPerformanceAnalysis:
    """Performance metrics for network analysis"""
    average_latency_ms: float
    jitter_ms: float
    packet_loss_percentage: float
    throughput_mbps: float
    connection_success_rate: float
    performance_score: float  # 0.0 (bad) to 1.0 (excellent)

@dataclass
class SecurityThreatAnalysis:
    """Security threat analysis results"""
    threat_level: str  # 'none', 'low', 'medium', 'high', 'critical'
    active_threats: List[str]
    confidence_score: float  # 0.0 to 1.0
    affected_assets: List[str]
    threat_details: Dict[str, any] = field(default_factory=dict)

@dataclass
class NetworkHealthReport:
    """Comprehensive network health assessment"""
    timestamp: datetime
    performance: NetworkPerformanceAnalysis
    security_status: SecurityThreatAnalysis
    overall_health_score: float  # 0.0 (critical) to 1.0 (excellent)
    correlation_insights: List[str]
    recommended_actions: List[str]
    performance_impact_of_attacks: Dict[str, float] = field(default_factory=dict)

class NetworkPerformanceAnalyzer:
    """Analyzes network performance metrics"""
    
    def __init__(self):
        # Performance tracking windows
        self.latency_history: deque = deque(maxlen=100)
        self.throughput_history: deque = deque(maxlen=100)
        self.connection_success_history: deque = deque(maxlen=100)
        
    async def analyze(self, flow_data: Dict) -> NetworkPerformanceAnalysis:
        """Analyze network performance from flow data"""
        try:
            # Extract performance metrics from flow data
            bandwidth_stats = flow_data.get('bandwidth_usage', {})
            flows = flow_data.get('flows', [])
            
            # Calculate throughput
            throughput_bps = bandwidth_stats.get('total_bytes_per_sec', 0.0)
            throughput_mbps = (throughput_bps * 8) / (1024 * 1024)  # Convert to Mbps
            
            # Estimate latency based on flow patterns (simplified)
            avg_latency = self._estimate_latency_from_flows(flows)
            
            # Calculate jitter
            jitter = self._calculate_jitter()
            
            # Estimate packet loss (simplified)
            packet_loss = self._estimate_packet_loss(flows)
            
            # Calculate connection success rate
            connection_success_rate = self._calculate_connection_success_rate(flows)
            
            # Calculate overall performance score
            performance_score = self._calculate_performance_score(
                avg_latency, jitter, packet_loss, throughput_mbps, connection_success_rate
            )
            
            # Update history
            self.latency_history.append(avg_latency)
            self.throughput_history.append(throughput_mbps)
            self.connection_success_history.append(connection_success_rate)
            
            return NetworkPerformanceAnalysis(
                average_latency_ms=avg_latency,
                jitter_ms=jitter,
                packet_loss_percentage=packet_loss,
                throughput_mbps=throughput_mbps,
                connection_success_rate=connection_success_rate,
                performance_score=performance_score
            )
            
        except Exception as e:
            logging.error(f"Error analyzing network performance: {e}")
            return self._get_default_performance_analysis()
    
    def _estimate_latency_from_flows(self, flows: List[Dict]) -> float:
        """Estimate average latency from flow characteristics"""
        if not flows:
            return 0.0
            
        # Simplified latency estimation based on connection setup times
        # In a real implementation, this would use actual RTT measurements
        tcp_flows = [f for f in flows if f.get('protocol') == 6]
        if tcp_flows:
            # Rough estimation: more flows with quick setup = lower latency
            avg_duration = sum(f.get('duration_seconds', 1.0) for f in tcp_flows) / len(tcp_flows)
            return min(avg_duration * 10, 200.0)  # Cap at 200ms
        return 20.0  # Default reasonable latency
    
    def _calculate_jitter(self) -> float:
        """Calculate network jitter from latency history"""
        if len(self.latency_history) < 2:
            return 0.0
        return statistics.stdev(list(self.latency_history)[-10:]) if len(self.latency_history) >= 2 else 0.0
    
    def _estimate_packet_loss(self, flows: List[Dict]) -> float:
        """Estimate packet loss percentage"""
        if not flows:
            return 0.0
            
        # Simplified: look for retransmissions or incomplete connections
        tcp_flows = [f for f in flows if f.get('protocol') == 6]
        if tcp_flows:
            incomplete_connections = sum(1 for f in tcp_flows 
                                       if f.get('connection_state', '').lower() in ['syn_sent', 'fin_wait'])
            return min((incomplete_connections / len(tcp_flows)) * 100, 10.0)  # Cap at 10%
        return 0.0
    
    def _calculate_connection_success_rate(self, flows: List[Dict]) -> float:
        """Calculate connection success rate"""
        tcp_flows = [f for f in flows if f.get('protocol') == 6]
        if not tcp_flows:
            return 1.0
            
        established_flows = sum(1 for f in tcp_flows 
                              if f.get('connection_state', '').lower() == 'established')
        return established_flows / len(tcp_flows) if tcp_flows else 1.0
    
    def _calculate_performance_score(self, latency: float, jitter: float, 
                                   packet_loss: float, throughput: float, 
                                   connection_success_rate: float) -> float:
        """Calculate overall performance score (0.0 to 1.0)"""
        # Weighted scoring
        latency_score = max(0.0, 1.0 - (latency / 100.0))  # 100ms = 0 score
        jitter_score = max(0.0, 1.0 - (jitter / 20.0))     # 20ms jitter = 0 score
        loss_score = max(0.0, 1.0 - (packet_loss / 5.0))   # 5% loss = 0 score
        throughput_score = min(1.0, throughput / 100.0)     # 100 Mbps = full score
        connection_score = connection_success_rate
        
        # Weighted average
        weights = [0.25, 0.15, 0.25, 0.20, 0.15]  # latency, jitter, loss, throughput, connections
        scores = [latency_score, jitter_score, loss_score, throughput_score, connection_score]
        
        return sum(w * s for w, s in zip(weights, scores))
    
    def _get_default_performance_analysis(self) -> NetworkPerformanceAnalysis:
        """Return default performance analysis on error"""
        return NetworkPerformanceAnalysis(
            average_latency_ms=0.0,
            jitter_ms=0.0,
            packet_loss_percentage=0.0,
            throughput_mbps=0.0,
            connection_success_rate=1.0,
            performance_score=0.5
        )

class IntelligentNetworkMonitor:
    """
    Superior monitoring system that combines security intelligence with performance analysis.
    Provides context-aware insights that go beyond traditional terminal tools.
    """
    
    def __init__(self):
        # Initialize security components
        self.ddos_detector = DDoSDetector()
        self.port_scan_detector = PortScanDetector()
        self.ml_integration_manager = MLIntegrationManager()
        
        # Initialize performance analyzer
        self.performance_analyzer = NetworkPerformanceAnalyzer()
        
        # Historical correlation data
        self.security_performance_correlations: deque = deque(maxlen=100)
        
        # Alert history for trend analysis
        self.recent_alerts: deque = deque(maxlen=50)
        
        logging.info("IntelligentNetworkMonitor initialized with security and performance analysis")
    
    async def analyze_network_health(self, flow_data: Dict) -> NetworkHealthReport:
        """
        Comprehensive network health analysis combining security and performance.
        This is the main entry point for intelligent monitoring.
        """
        try:
            # Extract security awareness data from Rust flow summary
            security_awareness = flow_data.get('security_awareness', {})
            
            # Use Rust-generated security metrics
            if security_awareness:
                security_insights = self._analyze_rust_security_data(security_awareness)
            else:
                # Fallback to Python-based security analysis
                security_insights = await self._analyze_security_threats(flow_data)
            
            # Analyze performance metrics
            performance_metrics = await self.performance_analyzer.analyze(flow_data)
            
            # Use health correlation from Rust or calculate our own
            health_correlation = security_awareness.get('network_health_correlation', {})
            if health_correlation:
                overall_health_score = health_correlation.get('health_score', 0.8)
                base_status_message = health_correlation.get('status_message', 'Network health optimal.')
            else:
                overall_health_score = self._calculate_composite_health_score(
                    performance_metrics, security_insights
                )
                base_status_message = "Network health analysis complete."
            
            # Calculate performance impact from security threats
            performance_impact = self._analyze_security_performance_correlation(
                security_insights, performance_metrics
            )
            
            # Generate intelligent insights combining Rust and Python analysis
            correlation_insights = [base_status_message]
            correlation_insights.extend(self._generate_correlation_insights(
                security_insights, performance_metrics, performance_impact
            ))
            
            # Generate actionable recommendations
            recommended_actions = self._generate_recommended_actions(
                security_insights, performance_metrics, overall_health_score
            )
            
            # Store correlation data for trend analysis
            self._store_correlation_data(security_insights, performance_metrics)
            
            return NetworkHealthReport(
                timestamp=datetime.utcnow(),
                performance=performance_metrics,
                security_status=security_insights,
                overall_health_score=overall_health_score,
                correlation_insights=correlation_insights,
                recommended_actions=recommended_actions,
                performance_impact_of_attacks=performance_impact
            )
            
        except Exception as e:
            logging.error(f"Error in network health analysis: {e}")
            return self._get_default_health_report()
    
    def _analyze_rust_security_data(self, security_awareness: Dict) -> SecurityThreatAnalysis:
        """Analyze security data from Rust security awareness metrics"""
        try:
            security_indicators = security_awareness.get('suspicious_activity_indicators', {})
            performance_impact = security_awareness.get('performance_impact_of_attacks', {})
            
            active_threats = []
            threat_level = 'none'
            
            # Check for DDoS attempts
            if security_indicators.get('is_ddos_attempt', False):
                active_threats.append('DDoS Attack')
                threat_level = 'high'
            
            # Check for port scanning
            if security_indicators.get('port_scan_detected', False):
                active_threats.append('Port Scanning')
                threat_level = 'medium' if threat_level == 'none' else threat_level
            
            # Get suspicious IPs
            suspicious_ips = security_indicators.get('suspicious_ips', [])
            affected_assets = [str(ip) for ip in suspicious_ips]
            
            # Calculate confidence based on impact metrics
            confidence_score = 0.85  # Default high confidence for Rust analysis
            if performance_impact.get('average_latency_ms', 0) > 0:
                confidence_score = min(confidence_score + 0.1, 1.0)
            
            threat_details = {
                'rust_security_indicators': security_indicators,
                'performance_impact': performance_impact
            }
            
            return SecurityThreatAnalysis(
                threat_level=threat_level,
                active_threats=active_threats,
                confidence_score=confidence_score,
                affected_assets=affected_assets,
                threat_details=threat_details
            )
            
        except Exception as e:
            logging.error(f"Error analyzing Rust security data: {e}")
            return SecurityThreatAnalysis(
                threat_level='unknown',
                active_threats=[],
                confidence_score=0.0,
                affected_assets=[]
            )
    
    async def _analyze_security_threats(self, flow_data: Dict) -> SecurityThreatAnalysis:
        """Analyze security threats using existing detection systems"""
        try:
            flows = flow_data.get('flows', [])
            bandwidth_stats = flow_data.get('bandwidth_usage', {})
            
            active_threats = []
            threat_details = {}
            
            # DDoS Detection
            ddos_alerts = self.ddos_detector.analyze_traffic_and_bandwidth(flows, bandwidth_stats)
            if ddos_alerts:
                active_threats.extend([f"DDoS: {alert.attack_type}" for alert in ddos_alerts])
                threat_details['ddos_alerts'] = [
                    {
                        'type': alert.attack_type,
                        'target': alert.target_ip,
                        'severity': alert.severity,
                        'confidence': alert.confidence
                    } for alert in ddos_alerts
                ]
            
            # Port Scan Detection
            port_scan_alerts = await self._detect_port_scans(flows)
            if port_scan_alerts:
                active_threats.extend(["Port Scanning"])
                threat_details['port_scan_alerts'] = port_scan_alerts
            
            # ML-based threat detection
            ml_threats = await self._detect_ml_threats(flow_data)
            if ml_threats:
                active_threats.extend(ml_threats)
                threat_details['ml_threats'] = ml_threats
            
            # Determine overall threat level
            threat_level = self._determine_threat_level(active_threats, ddos_alerts)
            
            # Calculate confidence score
            confidence_score = self._calculate_security_confidence(
                ddos_alerts, port_scan_alerts, ml_threats
            )
            
            # Identify affected assets
            affected_assets = self._identify_affected_assets(flows, ddos_alerts)
            
            return SecurityThreatAnalysis(
                threat_level=threat_level,
                active_threats=active_threats,
                confidence_score=confidence_score,
                affected_assets=affected_assets,
                threat_details=threat_details
            )
            
        except Exception as e:
            logging.error(f"Error in security threat analysis: {e}")
            return SecurityThreatAnalysis(
                threat_level='unknown',
                active_threats=[],
                confidence_score=0.0,
                affected_assets=[]
            )
    
    async def _detect_port_scans(self, flows: List[Dict]) -> List[Dict]:
        """Detect port scanning activities"""
        try:
            # Use existing port scan detector
            scan_alerts = self.port_scan_detector.analyze_flows(flows)
            return [
                {
                    'scanner_ip': alert.scanner_ip,
                    'target_ip': alert.target_ip,
                    'scan_type': alert.scan_type,
                    'confidence': alert.confidence
                } for alert in scan_alerts
            ]
        except Exception as e:
            logging.error(f"Error in port scan detection: {e}")
            return []
    
    async def _detect_ml_threats(self, flow_data: Dict) -> List[str]:
        """Detect threats using ML models"""
        try:
            # Use existing ML integration
            ml_results = await self.ml_integration_manager.analyze_flows_with_ml(flow_data)
            return [result.get('threat_type', 'Unknown') for result in ml_results 
                   if result.get('confidence', 0.0) > 0.7]
        except Exception as e:
            logging.error(f"Error in ML threat detection: {e}")
            return []
    
    def _determine_threat_level(self, active_threats: List[str], ddos_alerts: List) -> str:
        """Determine overall threat level"""
        if not active_threats:
            return 'none'
        
        # Check for critical threats
        critical_keywords = ['ddos', 'critical', 'high']
        if any(keyword in threat.lower() for threat in active_threats for keyword in critical_keywords):
            return 'critical'
        
        # Check DDoS severity
        if ddos_alerts:
            max_severity = max(alert.severity for alert in ddos_alerts)
            if max_severity in ['critical', 'high']:
                return max_severity
        
        # Default to medium if threats exist
        return 'medium' if len(active_threats) > 2 else 'low'
    
    def _calculate_security_confidence(self, ddos_alerts: List, 
                                     port_scan_alerts: List, ml_threats: List) -> float:
        """Calculate confidence in security analysis"""
        total_confidence = 0.0
        total_weight = 0.0
        
        # DDoS confidence
        if ddos_alerts:
            ddos_confidence = sum(alert.confidence for alert in ddos_alerts) / len(ddos_alerts)
            total_confidence += ddos_confidence * 0.4
            total_weight += 0.4
        
        # Port scan confidence
        if port_scan_alerts:
            scan_confidence = sum(alert.get('confidence', 0.8) for alert in port_scan_alerts) / len(port_scan_alerts)
            total_confidence += scan_confidence * 0.3
            total_weight += 0.3
        
        # ML confidence
        if ml_threats:
            total_confidence += 0.8 * 0.3  # Assume good ML confidence
            total_weight += 0.3
        
        return total_confidence / total_weight if total_weight > 0 else 0.8
    
    def _identify_affected_assets(self, flows: List[Dict], ddos_alerts: List) -> List[str]:
        """Identify network assets affected by security threats"""
        affected_assets = set()
        
        # From DDoS alerts
        for alert in ddos_alerts:
            if alert.target_ip:
                affected_assets.add(alert.target_ip)
        
        # From high-traffic flows
        for flow in flows:
            bytes_total = flow.get('bytes_sent', 0) + flow.get('bytes_received', 0)
            if bytes_total > 1000000:  # 1MB threshold
                affected_assets.add(flow.get('dst_ip', ''))
        
        return list(affected_assets)
    
    def _analyze_security_performance_correlation(self, 
                                                security_insights: SecurityThreatAnalysis,
                                                performance_metrics: NetworkPerformanceAnalysis) -> Dict[str, float]:
        """Analyze how security threats impact performance"""
        impact_analysis = {}
        
        # DDoS impact on bandwidth and latency
        if 'ddos' in str(security_insights.active_threats).lower():
            impact_analysis['bandwidth_impact'] = 1.0 - performance_metrics.performance_score
            impact_analysis['latency_impact'] = min(performance_metrics.average_latency_ms / 100.0, 1.0)
        
        # Port scan impact on connection success
        if any('port' in threat.lower() for threat in security_insights.active_threats):
            impact_analysis['connection_impact'] = 1.0 - performance_metrics.connection_success_rate
        
        return impact_analysis
    
    def _calculate_composite_health_score(self, 
                                        performance_metrics: NetworkPerformanceAnalysis,
                                        security_insights: SecurityThreatAnalysis) -> float:
        """Calculate overall network health score"""
        # Weight performance and security equally
        performance_weight = 0.6
        security_weight = 0.4
        
        # Security score based on threat level
        security_score_map = {
            'none': 1.0,
            'low': 0.8,
            'medium': 0.5,
            'high': 0.2,
            'critical': 0.0
        }
        security_score = security_score_map.get(security_insights.threat_level, 0.5)
        
        # Composite score
        composite_score = (
            performance_metrics.performance_score * performance_weight +
            security_score * security_weight
        )
        
        return round(composite_score, 3)
    
    def _generate_correlation_insights(self, 
                                     security_insights: SecurityThreatAnalysis,
                                     performance_metrics: NetworkPerformanceAnalysis,
                                     performance_impact: Dict[str, float]) -> List[str]:
        """Generate human-readable correlation insights"""
        insights = []
        
        # Performance-security correlations
        if performance_impact.get('bandwidth_impact', 0) > 0.3:
            insights.append(f"High bandwidth usage detected - likely DDoS attack causing "
                          f"{performance_impact['bandwidth_impact']*100:.1f}% performance degradation")
        
        if performance_impact.get('latency_impact', 0) > 0.3:
            insights.append(f"Increased latency ({performance_metrics.average_latency_ms:.1f}ms) "
                          f"correlates with security threats")
        
        if security_insights.threat_level in ['high', 'critical'] and performance_metrics.performance_score < 0.5:
            insights.append("Critical security threats are significantly impacting network performance")
        
        if performance_metrics.packet_loss_percentage > 2.0 and security_insights.active_threats:
            insights.append(f"Packet loss ({performance_metrics.packet_loss_percentage:.1f}%) "
                          f"may be caused by active security threats")
        
        return insights
    
    def _generate_recommended_actions(self, 
                                    security_insights: SecurityThreatAnalysis,
                                    performance_metrics: NetworkPerformanceAnalysis,
                                    overall_health_score: float) -> List[str]:
        """Generate actionable recommendations"""
        actions = []
        
        # Critical health score
        if overall_health_score < 0.3:
            actions.append("URGENT: Network health is critical - immediate intervention required")
        
        # Security-based actions
        if 'ddos' in str(security_insights.active_threats).lower():
            actions.append("Implement DDoS mitigation: rate limiting, traffic filtering")
            actions.append("Consider activating upstream DDoS protection services")
        
        if any('port' in threat.lower() for threat in security_insights.active_threats):
            actions.append("Block suspicious scanning IPs at firewall level")
            actions.append("Review and harden exposed services")
        
        # Performance-based actions
        if performance_metrics.packet_loss_percentage > 3.0:
            actions.append(f"Investigate packet loss ({performance_metrics.packet_loss_percentage:.1f}%) - check network equipment")
        
        if performance_metrics.average_latency_ms > 100:
            actions.append(f"High latency detected ({performance_metrics.average_latency_ms:.1f}ms) - optimize routing")
        
        return actions
    
    def _store_correlation_data(self, security_insights: SecurityThreatAnalysis, 
                               performance_metrics: NetworkPerformanceAnalysis):
        """Store correlation data for trend analysis"""
        correlation_point = {
            'timestamp': datetime.utcnow(),
            'threat_level': security_insights.threat_level,
            'performance_score': performance_metrics.performance_score,
            'active_threats_count': len(security_insights.active_threats)
        }
        self.security_performance_correlations.append(correlation_point)
    
    def _get_default_health_report(self) -> NetworkHealthReport:
        """Return default health report on error"""
        return NetworkHealthReport(
            timestamp=datetime.utcnow(),
            performance=NetworkPerformanceAnalysis(
                average_latency_ms=0.0,
                jitter_ms=0.0,
                packet_loss_percentage=0.0,
                throughput_mbps=0.0,
                connection_success_rate=1.0,
                performance_score=0.5
            ),
            security_status=SecurityThreatAnalysis(
                threat_level='unknown',
                active_threats=[],
                confidence_score=0.0,
                affected_assets=[]
            ),
            overall_health_score=0.5,
            correlation_insights=["Unable to analyze network health - check system status"],
            recommended_actions=["Verify monitoring system functionality"]
        ) 