# src/api/monitoring_endpoints.py
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio # For any async operations within endpoints

# Assuming SessionLocal is defined in your database setup
# and a dependency function get_db is available
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db # Adjust import path as per your project structure

# Import models for type hinting and potential direct queries if simple
from ..models import (
    BandwidthHistory, TopTalkersHistory, ProtocolDistributionHistory, 
    NetworkFlow as DBNetworkFlow, SecurityAlert as DBSecurityAlert
)

# Import security components (though analysis is mainly triggered by FlowProcessor)
from ..security.port_scan_detector import PortScanDetector
from ..security.ddos_detector import DDoSDetector
# Assuming ml_manager is initialized and accessible, e.g., via a dependency or global
from ..security.ml_integration_manager import setup_ml_models 

router = APIRouter(prefix="/api/monitoring", tags=["Monitoring & Analysis"])

# Initialize security detectors and ML manager if they are to be used directly by endpoints
# However, the main analysis path is via FlowProcessor. These might be for ad-hoc calls.
# For simplicity, let's assume FlowProcessor handles the main analysis pipeline.
# ml_manager = setup_ml_models() # This might be better initialized at app startup

# --- Database Helper Function Placeholders ---
# These would typically reside in a 'services' or 'crud' layer.

async def db_get_bandwidth_history(
    db: AsyncSession, start_time: datetime, end_time: datetime
) -> List[Dict[str, Any]]:
    # Placeholder: Query BandwidthHistory table
    # Example:
    # result = await db.execute(
    #     select(BandwidthHistory).filter(BandwidthHistory.timestamp.between(start_time, end_time)).order_by(BandwidthHistory.timestamp)
    # )
    # return [row._asdict() for row in result.scalars().all()] # Adjust based on your model and needs
    print(f"DB Placeholder: Fetching bandwidth history from {start_time} to {end_time}")
    return [{"timestamp": datetime.utcnow().isoformat(), "total_bytes_per_sec": 1000, "active_flows": 10}] 

async def db_get_protocol_distribution_history(
    db: AsyncSession, start_time: datetime, end_time: datetime
) -> List[Dict[str, Any]]:
    # Placeholder: Query ProtocolDistributionHistory table
    # This should return a list of records, where each record might represent a snapshot
    # containing multiple protocol stats for that timestamp.
    # Or, it could be a flat list of individual protocol stats over time.
    # The frontend HistoricalCharts expects the latest snapshot.
    print(f"DB Placeholder: Fetching protocol distribution from {start_time} to {end_time}")
    # Example for latest snapshot (adjust query for history if needed by frontend)
    return [{
        "timestamp": datetime.utcnow().isoformat(),
        "protocol_stats": [ # This structure matches what HistoricalCharts.jsx might expect for latest
            {"protocol_number": 6, "protocol_name": "TCP", "percentage": 70.5},
            {"protocol_number": 17, "protocol_name": "UDP", "percentage": 25.0}
        ]
    }]

async def db_get_top_talkers_history(
    db: AsyncSession, start_time: datetime, end_time: datetime
) -> List[Dict[str, Any]]:
    # Placeholder: Query TopTalkersHistory table
    # Similar to protocol distribution, this might be snapshots of top talkers.
    print(f"DB Placeholder: Fetching top talkers from {start_time} to {end_time}")
    return [{
        "timestamp": datetime.utcnow().isoformat(),
        "talkers": [ # This structure matches what HistoricalCharts.jsx might expect for latest
            {"ip_address": "192.168.1.101", "bytes_total": 500000, "rank_by_bytes": 1},
            {"ip_address": "10.0.0.5", "bytes_total": 300000, "rank_by_bytes": 2}
        ]
    }]

async def db_get_active_flows_summary(db: AsyncSession) -> List[Dict[str, Any]]:
    # Placeholder: Query NetworkFlow for "active" flows or use cached data from Redis if available
    # This is a complex query; "active" needs definition (e.g., last seen recently)
    print("DB Placeholder: Fetching active flows summary")
    return [
        {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": 17, "bytes_per_second": 100.0},
        {"src_ip": "192.168.1.102", "dst_ip": "1.1.1.1", "protocol": 6, "bytes_per_second": 2000.0}
    ]

async def db_get_recent_alerts_summary(db: AsyncSession, hours: int = 1) -> List[Dict[str, Any]]:
    # Placeholder: Query SecurityAlert table for recent alerts
    start_time = datetime.utcnow() - timedelta(hours=hours)
    print(f"DB Placeholder: Fetching alerts since {start_time}")
    return [
        {"alert_type": "port_scan", "severity": "medium", "timestamp": datetime.utcnow().isoformat()},
        {"alert_type": "ml_detection", "severity": "high", "timestamp": (datetime.utcnow()-timedelta(minutes=10)).isoformat()}
    ]

# --- API Endpoints ---

@router.get("/historical", response_model=Dict[str, Any])
async def get_historical_data(
    range_str: str = Query("1h", alias="range", regex="^(1h|6h|24h|7d)$"),
    # data_type: Optional[str] = Query(None), # Not used in current plan, can be added for specific data types
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical monitoring data for bandwidth, protocol distribution, and top talkers.
    The `range` query parameter specifies the time window (e.g., "1h", "6h", "24h", "7d").
    """
    now = datetime.utcnow()
    time_deltas = {
        "1h": timedelta(hours=1), "6h": timedelta(hours=6), 
        "24h": timedelta(days=1), "7d": timedelta(days=7)
    }
    start_time = now - time_deltas[range_str]
    
    try:
        # Fetch data concurrently
        bandwidth_task = db_get_bandwidth_history(db, start_time, now)
        protocol_task = db_get_protocol_distribution_history(db, start_time, now)
        top_talkers_task = db_get_top_talkers_history(db, start_time, now)
        
        bandwidth_history_data, protocol_distribution_data, top_talkers_data = await asyncio.gather(
            bandwidth_task, protocol_task, top_talkers_task
        )
        
        return {
            "bandwidth_history": bandwidth_history_data,
            "protocol_distribution_history": protocol_distribution_data, # Key matches frontend expectation
            "top_talkers_history": top_talkers_data, # Key matches frontend expectation
            "time_range_requested": range_str,
            "query_start_time": start_time.isoformat(),
            "query_end_time": now.isoformat()
        }
        
    except Exception as e:
        # Log the exception e
        raise HTTPException(status_code=500, detail=f"Failed to fetch historical data: {str(e)}")


@router.get("/network-summary", response_model=Dict[str, Any])
async def get_network_summary(db: AsyncSession = Depends(get_db)):
    """
    Get current network summary statistics including active flows, device count,
    total bandwidth, recent alerts, and top protocols.
    """
    try:
        active_flows_data = await db_get_active_flows_summary(db) # This needs a real implementation
        recent_alerts_data = await db_get_recent_alerts_summary(db, hours=1)

        total_devices = len(set(flow.get('src_ip') for flow in active_flows_data if flow.get('src_ip')) | 
                              set(flow.get('dst_ip') for flow in active_flows_data if flow.get('dst_ip')))
        
        total_bandwidth_bps = sum(flow.get('bytes_per_second', 0.0) * 8 for flow in active_flows_data) # Sum of Bps * 8 for bps

        protocol_counts: Dict[int, int] = {}
        for flow in active_flows_data:
            protocol = flow.get('protocol')
            if protocol is not None:
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        total_active_flows = len(active_flows_data)
        top_protocols_summary = sorted(
            [
                {"protocol": p, "count": c, "percentage": (c / total_active_flows) * 100 if total_active_flows > 0 else 0}
                for p, c in protocol_counts.items()
            ], 
            key=lambda x: x['count'], 
            reverse=True
        )[:5]
        
        return {
            "active_flows_count": total_active_flows,
            "estimated_total_devices": total_devices,
            "current_total_bandwidth_mbps": total_bandwidth_bps / 1_000_000, # Mbps
            "recent_alerts_count": len(recent_alerts_data),
            "critical_alerts_count": len([a for a in recent_alerts_data if a.get('severity') == 'critical']),
            "top_protocols": top_protocols_summary,
            "summary_timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        # Log the exception e
        raise HTTPException(status_code=500, detail=f"Failed to get network summary: {str(e)}")

# Note: The `/analyze-flows` endpoint from the user's original plan for Phase 3
# is largely superseded by the Redis FlowProcessor triggering analysis.
# If a manual trigger is still desired, it could be added here,
# but it would need careful consideration of how it interacts with the async FlowProcessor.
# For now, it's omitted as per the refined understanding that FlowProcessor is the primary path.

# Example: Ad-hoc analysis endpoint (if needed, ensure it's secured)
# @router.post("/trigger-analysis-on-demand", status_code=202)
# async def trigger_analysis_on_demand(
#     flows_data: Dict[str, Any], # Expects {"flows": [...], "bandwidth_stats": {...}}
#     db: AsyncSession = Depends(get_db)
# ):
#     """Manually triggers security analysis on a provided set of flow data."""
#     # This would be similar to what FlowProcessor's `trigger_security_analysis_service` does.
#     # Be cautious about direct exposure and resource usage.
#     asyncio.create_task(trigger_security_analysis_service(flows_data, db))
#     return {"message": "Security analysis triggered on demand."}