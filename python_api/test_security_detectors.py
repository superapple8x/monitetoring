#!/usr/bin/env python3
"""
Phase 3 Security Detection Testing Script
Tests port scan detection, DDoS detection, and ML integration with simulated attack scenarios
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from datetime import datetime, timedelta
from typing import List, Dict
import json

# Import security detectors
from app.security.port_scan_detector import PortScanDetector, PortScanAlert
from app.security.ddos_detector import DDoSDetector, DDoSAlert
from app.security.ml_integration_manager import MLIntegrationManager

def print_test_header(test_name: str):
    print(f"\n{'='*60}")
    print(f"🔍 {test_name}")
    print(f"{'='*60}")

def print_test_result(test_name: str, passed: bool, details: str = ""):
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} - {test_name}")
    if details:
        print(f"   Details: {details}")

def test_case_3_1_tcp_syn_scan():
    """Test Case 3.1: Port Scan Detection - TCP SYN Scan"""
    print_test_header("Test Case 3.1: TCP SYN Scan Detection")
    
    detector = PortScanDetector()
    
    # Simulate TCP SYN scan from 192.168.1.100 to 192.168.1.200 on 25+ ports
    flows = []
    scan_source = "192.168.1.100"
    scan_target = "192.168.1.200"
    
    # Generate SYN scan flows targeting 25 different ports
    for port in range(22, 47):  # 25 ports: 22-46
        flows.append({
            'src_ip': scan_source,
            'dst_ip': scan_target,
            'dst_port': port,
            'protocol': 6,  # TCP
            'connection_state': 'syn_sent',
            'duration': 0.1,
            'bytes_sent': 64,
            'packets_sent': 1
        })
    
    # Add some normal traffic to test filtering
    flows.extend([
        {'src_ip': '192.168.1.50', 'dst_ip': '192.168.1.200', 'dst_port': 80, 'protocol': 6, 'connection_state': 'established', 'duration': 5.0},
        {'src_ip': '192.168.1.51', 'dst_ip': '192.168.1.201', 'dst_port': 443, 'protocol': 6, 'connection_state': 'established', 'duration': 3.0}
    ])
    
    alerts = detector.analyze_flows(flows)
    
    # Verify results
    tcp_syn_alerts = [alert for alert in alerts if alert.scan_type == 'tcp_syn']
    passed = len(tcp_syn_alerts) > 0
    
    if passed:
        alert = tcp_syn_alerts[0]
        details = f"Detected scan from {alert.source_ip} to {alert.target_ip}, {len(alert.scanned_ports)} ports, confidence: {alert.confidence}"
        print(f"   🎯 Alert Details: {alert.scan_type} scan, severity: {alert.severity}")
        print(f"   📊 Scanned ports: {alert.scanned_ports[:10]}{'...' if len(alert.scanned_ports) > 10 else ''}")
    else:
        details = f"No TCP SYN scan alerts detected from {len(flows)} flows"
    
    print_test_result("TCP SYN Scan Detection", passed, details)
    return passed

def test_case_3_2_udp_scan():
    """Test Case 3.2: Port Scan Detection - UDP Scan"""
    print_test_header("Test Case 3.2: UDP Scan Detection")
    
    detector = PortScanDetector()
    
    # Simulate UDP scan from 10.0.0.100 to 10.0.0.200 on 30+ ports
    flows = []
    scan_source = "10.0.0.100"
    scan_target = "10.0.0.200"
    
    # Generate UDP scan flows targeting 30 different ports
    for port in range(1000, 1030):  # 30 ports: 1000-1029
        flows.append({
            'src_ip': scan_source,
            'dst_ip': scan_target,
            'dst_port': port,
            'protocol': 17,  # UDP
            'connection_state': 'unknown',
            'duration': 0.05,
            'bytes_sent': 32,
            'packets_sent': 1
        })
    
    alerts = detector.analyze_flows(flows)
    
    # Verify results
    udp_alerts = [alert for alert in alerts if alert.scan_type == 'udp']
    passed = len(udp_alerts) > 0
    
    if passed:
        alert = udp_alerts[0]
        details = f"Detected scan from {alert.source_ip} to {alert.target_ip}, {len(alert.scanned_ports)} ports, confidence: {alert.confidence}"
        print(f"   🎯 Alert Details: {alert.scan_type} scan, severity: {alert.severity}")
    else:
        details = f"No UDP scan alerts detected from {len(flows)} flows"
    
    print_test_result("UDP Scan Detection", passed, details)
    return passed

def test_case_3_3_port_sweep():
    """Test Case 3.3: Port Scan Detection - Port Sweep"""
    print_test_header("Test Case 3.3: Port Sweep Detection")
    
    detector = PortScanDetector()
    
    # Simulate port sweep from 172.16.1.100 targeting port 445 on 15+ different IPs
    flows = []
    scan_source = "172.16.1.100"
    target_port = 445
    
    # Generate port sweep flows targeting 15 different IPs on same port
    for ip_suffix in range(1, 16):  # 15 IPs: 172.16.1.1 to 172.16.1.15
        flows.append({
            'src_ip': scan_source,
            'dst_ip': f'172.16.1.{ip_suffix}',
            'dst_port': target_port,
            'protocol': 6,  # TCP
            'connection_state': 'syn_sent',
            'duration': 0.1,
            'bytes_sent': 64,
            'packets_sent': 1
        })
    
    alerts = detector.analyze_flows(flows)
    
    # Verify results
    sweep_alerts = [alert for alert in alerts if alert.scan_type == 'port_sweep']
    passed = len(sweep_alerts) > 0
    
    if passed:
        alert = sweep_alerts[0]
        details = f"Detected sweep from {alert.source_ip} on port {alert.scanned_ports[0]}, targeting {alert.target_ip}"
        print(f"   🎯 Alert Details: {alert.scan_type}, severity: {alert.severity}")
        print(f"   📊 Swept port: {alert.scanned_ports[0]}")
    else:
        details = f"No port sweep alerts detected from {len(flows)} flows"
    
    print_test_result("Port Sweep Detection", passed, details)
    return passed

def test_case_3_4_ddos_volumetric():
    """Test Case 3.4: DDoS Detection - Volumetric Attack"""
    print_test_header("Test Case 3.4: DDoS Volumetric Attack Detection")
    
    detector = DDoSDetector()
    
    # First, establish baseline with normal traffic for several windows
    print("   📊 Establishing baseline traffic patterns...")
    for i in range(35):  # Build baseline history
        normal_flows = [
            {'src_ip': f'192.168.1.{j}', 'dst_ip': '203.0.113.1', 'protocol': 6, 
             'bytes_sent': 1000, 'packets_sent': 10, 'connection_state': 'established', 'dst_port': 80}
            for j in range(10, 15)  # 5 normal sources
        ]
        normal_bw_stats = {
            'total_bytes_this_window': 5000,  # 5KB total
            'total_packets_this_window': 50   # 50 packets total
        }
        
        # Force window completion for baseline building
        detector.current_window_start_time -= detector.detection_window_duration
        alerts = detector.analyze_traffic_and_bandwidth(normal_flows, normal_bw_stats)
    
    print(f"   📈 Baseline established with {len(detector.bandwidth_history)} data points")
    
    # Now simulate volumetric attack (10x normal traffic)
    print("   🚨 Simulating volumetric attack (10x baseline)...")
    attack_flows = []
    
    # Generate high-volume attack traffic from multiple sources
    for j in range(50):  # 50 attacking sources
        attack_flows.append({
            'src_ip': f'1.2.3.{j}',
            'dst_ip': '203.0.113.1',  # Same target as baseline
            'protocol': 6,
            'bytes_sent': 10000,  # 10x normal
            'packets_sent': 100,  # 10x normal
            'connection_state': 'syn_sent',
            'dst_port': 80
        })
    
    attack_bw_stats = {
        'total_bytes_this_window': 500000,  # 500KB (100x baseline)
        'total_packets_this_window': 5000   # 5000 packets (100x baseline)
    }
    
    # Force window completion to trigger analysis
    detector.current_window_start_time -= detector.detection_window_duration
    alerts = detector.analyze_traffic_and_bandwidth(attack_flows, attack_bw_stats)
    
    # Verify results
    volumetric_alerts = [alert for alert in alerts if alert.attack_type == 'volumetric']
    passed = len(volumetric_alerts) > 0
    
    if passed:
        alert = volumetric_alerts[0]
        details = f"Detected attack against {alert.target_ip}, peak: {alert.peak_rate:.0f}, baseline: {alert.baseline_rate:.0f}, amplification: {alert.amplification_factor:.1f}x"
        print(f"   🎯 Alert Details: {alert.attack_type} attack, severity: {alert.severity}")
        print(f"   📊 Attack vectors: {alert.attack_vectors}")
    else:
        details = f"No volumetric DDoS alerts detected from attack simulation"
    
    print_test_result("Volumetric DDoS Detection", passed, details)
    return passed

def test_case_3_5_ddos_syn_flood():
    """Test Case 3.5: DDoS Detection - SYN Flood"""
    print_test_header("Test Case 3.5: DDoS SYN Flood Detection")
    
    detector = DDoSDetector()
    
    # Lower the SYN flood threshold for testing
    original_threshold = detector.syn_flood_pps_threshold
    detector.syn_flood_pps_threshold = 50  # Lower threshold for testing
    print(f"   🔧 Adjusted SYN flood threshold from {original_threshold} to {detector.syn_flood_pps_threshold} for testing")
    
    # Establish minimal baseline
    for i in range(10):
        normal_flows = [
            {'src_ip': '192.168.1.10', 'dst_ip': '192.168.1.100', 'protocol': 6, 
             'bytes_sent': 500, 'packets_sent': 5, 'connection_state': 'established', 'dst_port': 80}
        ]
        normal_bw_stats = {'total_bytes_this_window': 500, 'total_packets_this_window': 5}
        detector.current_window_start_time -= detector.detection_window_duration
        detector.analyze_traffic_and_bandwidth(normal_flows, normal_bw_stats)
    
    print("   📊 Baseline established for SYN flood detection")
    
    # Simulate SYN flood attack with higher SYN packet rate
    print("   🚨 Simulating SYN flood attack...")
    syn_flood_flows = []
    target_ip = '192.168.1.100'
    
    # Generate high-rate SYN packets from multiple sources to single target
    # Need to generate enough SYN packets to exceed 50 packets/second over 1 minute window
    for j in range(200):  # 200 attacking sources
        syn_flood_flows.append({
            'src_ip': f'10.0.{j//50}.{j%50}',  # Distributed sources
            'dst_ip': target_ip,
            'protocol': 6,  # TCP
            'bytes_sent': 64,
            'packets_sent': 5,  # 5 SYN packets per source
            'connection_state': 'syn_sent',  # SYN flood indicator
            'dst_port': 80
        })
    
    # Total SYN packets = 200 sources * 5 packets = 1000 SYN packets
    # Over 60 seconds = 1000/60 = 16.67 packets/sec (still below 50)
    # Let's increase packets per source
    for flow in syn_flood_flows:
        flow['packets_sent'] = 20  # 20 SYN packets per source
    
    # Now: 200 sources * 20 packets = 4000 SYN packets over 60 seconds = 66.67 packets/sec > 50
    
    syn_flood_bw_stats = {
        'total_bytes_this_window': 200 * 64,   # 200 * 64 bytes
        'total_packets_this_window': 200 * 20  # 200 * 20 packets = 4000 total
    }
    
    print(f"   📊 Generated {len(syn_flood_flows)} SYN flows with {syn_flood_bw_stats['total_packets_this_window']} total SYN packets")
    expected_syn_pps = syn_flood_bw_stats['total_packets_this_window'] / 60  # Over 1 minute
    print(f"   📈 Expected SYN rate: {expected_syn_pps:.1f} packets/sec (threshold: {detector.syn_flood_pps_threshold})")
    
    # Force window completion
    detector.current_window_start_time -= detector.detection_window_duration
    alerts = detector.analyze_traffic_and_bandwidth(syn_flood_flows, syn_flood_bw_stats)
    
    # Debug: Check what SYN packets were counted
    total_syn_packets = sum(stats.syn_packets for stats in detector.current_window_source_ip_stats.values())
    print(f"   🔍 Debug: Total SYN packets counted: {total_syn_packets}")
    print(f"   🔍 Debug: SYN packets per target: {dict(detector.current_window_target_syn_counts)}")
    print(f"   🔍 Debug: Generated {len(alerts)} alerts: {[alert.attack_type + ':' + str(alert.attack_vectors) for alert in alerts]}")
    
    # Verify results
    syn_flood_alerts = [alert for alert in alerts if 'syn_flood' in alert.attack_vectors]
    passed = len(syn_flood_alerts) > 0
    
    if passed:
        alert = syn_flood_alerts[0]
        details = f"Detected SYN flood against {alert.target_ip}, {len(alert.source_ips)} attacking sources, rate: {alert.peak_rate:.1f} pps"
        print(f"   🎯 Alert Details: {alert.attack_type} attack, severity: {alert.severity}")
        print(f"   📊 Attack vectors: {alert.attack_vectors}")
        print(f"   📈 Peak SYN rate: {alert.peak_rate:.1f} packets/sec")
    else:
        details = f"No SYN flood alerts detected from attack simulation (expected rate: {expected_syn_pps:.1f} pps)"
    
    # Restore original threshold
    detector.syn_flood_pps_threshold = original_threshold
    
    print_test_result("SYN Flood Detection", passed, details)
    return passed

async def test_case_3_6_ml_integration():
    """Test Case 3.6: ML Integration Framework"""
    print_test_header("Test Case 3.6: ML Integration Framework")
    
    try:
        # Initialize ML integration manager
        ml_manager = MLIntegrationManager()
        
        # Test model registration
        print("   🤖 Testing ML model registration...")
        active_models = ml_manager.get_active_models()
        print(f"   📊 Active models: {[model.model_name for model in active_models]}")
        
        # Test flow analysis with placeholder model
        print("   🔍 Testing ML flow analysis...")
        sample_flow = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.200',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 6,
            'bytes_sent': 1500,
            'packets_sent': 15,
            'duration': 2.5,
            'connection_state': 'established'
        }
        
        alerts = await ml_manager.analyze_flow_with_ml(sample_flow)
        
        passed = True  # Framework test - should not crash
        details = f"ML framework operational, {len(active_models)} models registered, {len(alerts)} alerts generated"
        
        if alerts:
            print(f"   🎯 Generated {len(alerts)} ML-based alerts")
            for alert in alerts[:2]:  # Show first 2 alerts
                print(f"      - {alert.get('alert_type', 'unknown')}: {alert.get('description', 'No description')}")
        
    except Exception as e:
        passed = False
        details = f"ML integration failed: {str(e)}"
    
    print_test_result("ML Integration Framework", passed, details)
    return passed

async def run_comprehensive_security_tests():
    """Run all Phase 3 security detection tests"""
    print("🚀 Starting Phase 3 Security Detection Testing")
    print("=" * 80)
    
    test_results = []
    
    # Run all test cases
    test_results.append(test_case_3_1_tcp_syn_scan())
    test_results.append(test_case_3_2_udp_scan())
    test_results.append(test_case_3_3_port_sweep())
    test_results.append(test_case_3_4_ddos_volumetric())
    test_results.append(test_case_3_5_ddos_syn_flood())
    test_results.append(await test_case_3_6_ml_integration())
    
    # Summary
    print(f"\n{'='*80}")
    print("📊 PHASE 3 SECURITY TESTING SUMMARY")
    print(f"{'='*80}")
    
    passed_count = sum(test_results)
    total_count = len(test_results)
    
    print(f"✅ Tests Passed: {passed_count}/{total_count}")
    print(f"❌ Tests Failed: {total_count - passed_count}/{total_count}")
    
    if passed_count == total_count:
        print("🎉 ALL SECURITY DETECTION TESTS PASSED!")
        print("🛡️  Phase 3 security framework is fully operational")
    else:
        print("⚠️  Some security detection tests failed")
        print("🔧 Review failed components before production deployment")
    
    return passed_count == total_count

if __name__ == "__main__":
    import asyncio
    success = asyncio.run(run_comprehensive_security_tests())
    sys.exit(0 if success else 1) 