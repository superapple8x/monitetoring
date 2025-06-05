# src/api/security_endpoints.py
from fastapi import APIRouter, HTTPException, Query, Depends, Path, Body
from typing import List, Optional, Dict, Any
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db # Adjust import path as per your project structure
from ..models import SecurityAlert as DBSecurityAlert # SQLAlchemy model

# Pydantic models for request/response if needed, or use Dict[str, Any] for simplicity
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/security", tags=["Security Alerts"])

class AlertAcknowledgeRequest(BaseModel):
    acknowledged_by: str = Field(..., min_length=1, max_length=100)

# --- Database Helper Function Placeholders ---
# These would typically reside in a 'services' or 'crud' layer for alerts.

async def db_get_alerts(
    db: AsyncSession,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    alert_type: Optional[str] = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    # Placeholder: Query SecurityAlert table with filtering and sorting
    print(f"DB Placeholder: Fetching alerts with filters: severity={severity}, ack={acknowledged}, type={alert_type}, sort={sort_by} {sort_order}")
    # Example (very basic, real query would be more complex using SQLAlchemy):
    # query = select(DBSecurityAlert)
    # if severity: query = query.filter(DBSecurityAlert.severity == severity)
    # if acknowledged is not None: query = query.filter(DBSecurityAlert.is_acknowledged == acknowledged)
    # if alert_type: query = query.filter(DBSecurityAlert.alert_type == alert_type)
    # order_column = getattr(DBSecurityAlert, sort_by, DBSecurityAlert.timestamp)
    # query = query.order_by(desc(order_column) if sort_order == "desc" else asc(order_column))
    # query = query.limit(limit).offset(offset)
    # result = await db.execute(query)
    # return [row._asdict() for row in result.scalars().all()]
    
    # Dummy data for now:
    dummy_alerts = [
        {"id": 1, "timestamp": datetime.utcnow().isoformat(), "alert_type": "port_scan", "severity": "medium", "description": "Port scan from 1.2.3.4", "is_acknowledged": False, "details": {"scanned_ports": [80,443]}},
        {"id": 2, "timestamp": (datetime.utcnow()-timedelta(hours=1)).isoformat(), "alert_type": "ml_detection", "severity": "high", "description": "ML Anomaly detected for 10.0.0.5", "is_acknowledged": True, "acknowledged_by": "admin", "acknowledged_at": datetime.utcnow().isoformat(), "details": {"score": 0.9}},
    ]
    filtered_alerts = dummy_alerts
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
    if acknowledged is not None:
        filtered_alerts = [a for a in filtered_alerts if a['is_acknowledged'] == acknowledged]
    # Add more filtering/sorting for dummy data if needed for testing frontend
    return filtered_alerts[:limit]


async def db_get_alert_by_id(db: AsyncSession, alert_id: int) -> Optional[Dict[str, Any]]:
    # Placeholder: Fetch a single alert by ID
    print(f"DB Placeholder: Fetching alert with ID {alert_id}")
    # result = await db.execute(select(DBSecurityAlert).filter(DBSecurityAlert.id == alert_id))
    # record = result.scalars().first()
    # return record._asdict() if record else None
    alerts = await db_get_alerts(db) # Get dummy alerts
    for alert in alerts:
        if alert['id'] == alert_id:
            return alert
    return None

async def db_acknowledge_alert(db: AsyncSession, alert_id: int, acknowledged_by: str) -> Optional[Dict[str, Any]]:
    # Placeholder: Update alert to acknowledged
    print(f"DB Placeholder: Acknowledging alert ID {alert_id} by {acknowledged_by}")
    # alert = await db_get_alert_by_id(db, alert_id) # Fetch first
    # if alert and not alert.is_acknowledged:
    #     alert.is_acknowledged = True
    #     alert.acknowledged_by = acknowledged_by
    #     alert.acknowledged_at = datetime.utcnow()
    #     await db.commit()
    #     await db.refresh(alert) # If 'alert' is the SQLAlchemy model instance
    #     return alert._asdict()
    # return None
    # For dummy data, just return a success-like structure
    alert = await db_get_alert_by_id(db, alert_id)
    if alert:
        alert['is_acknowledged'] = True
        alert['acknowledged_by'] = acknowledged_by
        alert['acknowledged_at'] = datetime.utcnow().isoformat()
        return alert
    return None


async def db_delete_alert(db: AsyncSession, alert_id: int) -> bool:
    # Placeholder: Delete an alert
    print(f"DB Placeholder: Deleting alert ID {alert_id}")
    # alert = await db_get_alert_by_id(db, alert_id) # Fetch first
    # if alert:
    #     await db.delete(alert) # If 'alert' is the SQLAlchemy model instance
    #     await db.commit()
    #     return True
    # return False
    # For dummy data:
    return True # Assume success

# --- API Endpoints ---

@router.get("/alerts", response_model=List[Dict[str, Any]]) # Using Dict for now, can be Pydantic model
async def get_security_alerts(
    severity: Optional[str] = Query(None, enum=["critical", "high", "medium", "low"]),
    acknowledged: Optional[bool] = Query(None),
    alert_type: Optional[str] = Query(None, min_length=3, max_length=50),
    sort_by: str = Query("timestamp", enum=["timestamp", "severity", "alert_type"]),
    sort_order: str = Query("desc", enum=["asc", "desc"]),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve a list of security alerts with filtering, sorting, and pagination.
    """
    try:
        alerts_data = await db_get_alerts(
            db, severity, acknowledged, alert_type, sort_by, sort_order, limit, offset
        )
        return alerts_data
    except Exception as e:
        # Log exception e
        raise HTTPException(status_code=500, detail=f"Failed to fetch security alerts: {str(e)}")

@router.post("/alerts/{alert_id}/acknowledge", response_model=Dict[str, Any])
async def acknowledge_security_alert(
    alert_id: int = Path(..., ge=1, description="The ID of the alert to acknowledge"),
    request_body: AlertAcknowledgeRequest = Body(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Acknowledge a specific security alert.
    """
    try:
        updated_alert = await db_acknowledge_alert(db, alert_id, request_body.acknowledged_by)
        if not updated_alert:
            raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found or already acknowledged.")
        return updated_alert
    except HTTPException:
        raise # Re-raise HTTPException if already handled (like 404)
    except Exception as e:
        # Log exception e
        raise HTTPException(status_code=500, detail=f"Failed to acknowledge alert: {str(e)}")


@router.delete("/alerts/{alert_id}", status_code=204) # 204 No Content for successful deletion
async def delete_security_alert(
    alert_id: int = Path(..., ge=1, description="The ID of the alert to delete"),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete/Dismiss a specific security alert.
    """
    try:
        success = await db_delete_alert(db, alert_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")
        return None # Return None for 204 status code
    except HTTPException:
        raise
    except Exception as e:
        # Log exception e
        raise HTTPException(status_code=500, detail=f"Failed to delete alert: {str(e)}")

# Example: Endpoint to get a single alert's details (optional)
@router.get("/alerts/{alert_id}", response_model=Dict[str, Any])
async def get_single_alert_details(
    alert_id: int = Path(..., ge=1, description="The ID of the alert"),
    db: AsyncSession = Depends(get_db)
):
    try:
        alert = await db_get_alert_by_id(db, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")
        return alert
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alert details: {str(e)}")