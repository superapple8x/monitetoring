# src/api/intelligent_monitoring_endpoints.py
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from ..monitoring.intelligent_network_monitor import NetworkHealthReport, NetworkPerformanceAnalysis, SecurityThreatAnalysis

router = APIRouter(prefix="/api/v1/intelligent-monitoring", tags=["Intelligent Monitoring"])

# Pydantic models for API responses
class NetworkHealthResponse(BaseModel):
    """API response model for network health data"""
    timestamp: datetime
    overall_health_score: float = Field(..., ge=0.0, le=1.0, description="Overall network health score (0.0-1.0)")
    security_status: Dict[str, Any] = Field(..., description="Security threat analysis")
    performance_metrics: Dict[str, Any] = Field(..., description="Network performance metrics")
    correlation_insights: list[str] = Field(..., description="Intelligent correlation insights")
    recommended_actions: list[str] = Field(..., description="Recommended actions")
    performance_impact_of_attacks: Dict[str, float] = Field(default_factory=dict, description="Performance impact analysis")

class NetworkInsightsResponse(BaseModel):
    """API response model for network insights summary"""
    current_health_score: float
    threat_level: str
    active_threats_count: int
    performance_score: float
    key_insights: list[str]
    urgent_actions: list[str]

# Global reference to flow processor (will be set during startup)
_flow_processor = None

def set_flow_processor(processor):
    """Set the global flow processor reference"""
    global _flow_processor
    _flow_processor = processor

def get_flow_processor():
    """Get the flow processor dependency"""
    if _flow_processor is None:
        raise HTTPException(status_code=503, detail="Flow processor not available")
    return _flow_processor

@router.get("/health-report", response_model=NetworkHealthResponse)
async def get_network_health_report(processor = Depends(get_flow_processor)):
    """
    Get the latest comprehensive network health report.
    
    This endpoint provides intelligent analysis combining security and performance data,
    offering insights that go beyond traditional monitoring tools.
    """
    try:
        health_report = processor.get_latest_health_report()
        
        if health_report is None:
            raise HTTPException(
                status_code=404, 
                detail="No network health data available yet. Please wait for data collection to begin."
            )
        
        return NetworkHealthResponse(
            timestamp=health_report.timestamp,
            overall_health_score=health_report.overall_health_score,
            security_status={
                "threat_level": health_report.security_status.threat_level,
                "active_threats": health_report.security_status.active_threats,
                "confidence_score": health_report.security_status.confidence_score,
                "affected_assets": health_report.security_status.affected_assets,
                "threat_details": health_report.security_status.threat_details
            },
            performance_metrics={
                "average_latency_ms": health_report.performance.average_latency_ms,
                "jitter_ms": health_report.performance.jitter_ms,
                "packet_loss_percentage": health_report.performance.packet_loss_percentage,
                "throughput_mbps": health_report.performance.throughput_mbps,
                "connection_success_rate": health_report.performance.connection_success_rate,
                "performance_score": health_report.performance.performance_score
            },
            correlation_insights=health_report.correlation_insights,
            recommended_actions=health_report.recommended_actions,
            performance_impact_of_attacks=health_report.performance_impact_of_attacks
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving network health report: {str(e)}")

@router.get("/insights-summary", response_model=NetworkInsightsResponse)
async def get_network_insights_summary(processor = Depends(get_flow_processor)):
    """
    Get a concise summary of key network insights.
    
    This endpoint provides a quick overview of the most important network health indicators
    and actionable insights for network administrators.
    """
    try:
        health_report = processor.get_latest_health_report()
        
        if health_report is None:
            raise HTTPException(
                status_code=404, 
                detail="No network insights available yet. Please wait for data collection to begin."
            )
        
        # Extract key insights (first 3 most important)
        key_insights = health_report.correlation_insights[:3]
        
        # Extract urgent actions (those marked as urgent or critical)
        urgent_actions = [
            action for action in health_report.recommended_actions 
            if any(keyword in action.lower() for keyword in ['urgent', 'critical', 'immediate'])
        ]
        
        return NetworkInsightsResponse(
            current_health_score=health_report.overall_health_score,
            threat_level=health_report.security_status.threat_level,
            active_threats_count=len(health_report.security_status.active_threats),
            performance_score=health_report.performance.performance_score,
            key_insights=key_insights,
            urgent_actions=urgent_actions
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving network insights: {str(e)}")

@router.get("/security-analysis")
async def get_security_analysis(processor = Depends(get_flow_processor)):
    """
    Get detailed security analysis with threat intelligence.
    
    This endpoint provides comprehensive security analysis including threat detection,
    confidence scoring, and affected asset identification.
    """
    try:
        health_report = processor.get_latest_health_report()
        
        if health_report is None:
            raise HTTPException(
                status_code=404, 
                detail="No security analysis available yet. Please wait for data collection to begin."
            )
        
        security_status = health_report.security_status
        
        return {
            "timestamp": health_report.timestamp.isoformat(),
            "threat_assessment": {
                "overall_threat_level": security_status.threat_level,
                "confidence_score": security_status.confidence_score,
                "threat_count": len(security_status.active_threats)
            },
            "active_threats": [
                {
                    "threat_type": threat,
                    "severity": "high" if "ddos" in threat.lower() else "medium",
                    "detected_at": health_report.timestamp.isoformat()
                }
                for threat in security_status.active_threats
            ],
            "affected_infrastructure": {
                "asset_count": len(security_status.affected_assets),
                "affected_assets": security_status.affected_assets
            },
            "threat_intelligence": security_status.threat_details,
            "performance_impact": health_report.performance_impact_of_attacks,
            "mitigation_recommendations": [
                action for action in health_report.recommended_actions
                if any(keyword in action.lower() for keyword in ['block', 'filter', 'mitigate', 'protect'])
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving security analysis: {str(e)}")

@router.get("/performance-correlation")
async def get_performance_correlation(processor = Depends(get_flow_processor)):
    """
    Get performance analysis with security correlation.
    
    This endpoint shows how security events correlate with network performance,
    providing insights into the impact of threats on network operations.
    """
    try:
        health_report = processor.get_latest_health_report()
        
        if health_report is None:
            raise HTTPException(
                status_code=404, 
                detail="No performance correlation data available yet. Please wait for data collection to begin."
            )
        
        performance = health_report.performance
        security = health_report.security_status
        
        return {
            "timestamp": health_report.timestamp.isoformat(),
            "performance_overview": {
                "overall_score": performance.performance_score,
                "latency_ms": performance.average_latency_ms,
                "throughput_mbps": performance.throughput_mbps,
                "packet_loss_percent": performance.packet_loss_percentage,
                "connection_success_rate": performance.connection_success_rate
            },
            "security_impact_analysis": {
                "threats_affecting_performance": len(security.active_threats) > 0 and performance.performance_score < 0.7,
                "performance_degradation": health_report.performance_impact_of_attacks,
                "correlation_strength": "high" if len(security.active_threats) > 0 and performance.performance_score < 0.5 else "low"
            },
            "intelligent_insights": health_report.correlation_insights,
            "optimization_recommendations": [
                action for action in health_report.recommended_actions
                if any(keyword in action.lower() for keyword in ['optimize', 'improve', 'enhance', 'latency'])
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving performance correlation: {str(e)}")

@router.get("/health-status")
async def get_health_status(processor = Depends(get_flow_processor)):
    """
    Get a simple health status check for monitoring dashboards.
    
    This endpoint provides a quick health check suitable for status displays
    and automated monitoring systems.
    """
    try:
        health_report = processor.get_latest_health_report()
        
        if health_report is None:
            return {
                "status": "initializing",
                "message": "Network monitoring is starting up",
                "health_score": 0.5,
                "last_update": None
            }
        
        # Determine status based on health score
        if health_report.overall_health_score >= 0.8:
            status = "excellent"
            message = "Network is operating optimally"
        elif health_report.overall_health_score >= 0.6:
            status = "good"
            message = "Network is performing well"
        elif health_report.overall_health_score >= 0.4:
            status = "warning"
            message = "Network performance needs attention"
        else:
            status = "critical"
            message = "Network requires immediate attention"
        
        return {
            "status": status,
            "message": message,
            "health_score": health_report.overall_health_score,
            "threat_level": health_report.security_status.threat_level,
            "active_threats": len(health_report.security_status.active_threats),
            "last_update": health_report.timestamp.isoformat(),
            "requires_action": len(health_report.recommended_actions) > 0
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving health status: {str(e)}") 