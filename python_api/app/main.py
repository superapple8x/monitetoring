import asyncio
import json
import logging
import os
from typing import List, Dict, Optional, AsyncGenerator
from datetime import datetime, timedelta

import redis.asyncio as aioredis
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, sessionmaker
from .database import SessionLocal, get_db
from .models import Device, NetworkInterfaceMetric

# Import Phase 3 components
from .redis.flow_processor import FlowProcessor
from .api.monitoring_endpoints import router as monitoring_router
from .api.security_endpoints import router as security_router

# Import Phase 4 intelligent monitoring
from .api.intelligent_monitoring_endpoints import router as intelligent_monitoring_router, set_flow_processor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment Variables
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
NETWORK_METRICS_CHANNEL = "network_metrics_channel"
DEVICE_DISCOVERY_CHANNEL = "device_discovery_channel"
NETWORK_FLOWS_CHANNEL = "network_flows"

# --- Pydantic Models for Redis Data ---
class PublishedFlowKey(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

class PublishedFlowData(BaseModel):
    packet_count: int
    byte_count: int
    first_seen: int
    last_seen: int

class PublishedFlow(BaseModel):
    key: PublishedFlowKey
    data: PublishedFlowData

class PublishedInterfaceMetrics(BaseModel):
    timestamp: int # Unix timestamp from Rust
    interface_name: str
    packets_in: int
    packets_out: int
    bytes_in: int
    bytes_out: int
    active_flows: List[PublishedFlow] = Field(default_factory=list)

class PublishedDiscoveredDevice(BaseModel):
    ip_addr: str
    mac_addr: str
    last_seen: int # Unix timestamp from Rust
    timestamp: int # Publication timestamp from Rust

# Initialize FastAPI app
app = FastAPI(title="Network Monitoring API - Phase 3", version="3.0.0")

# --- CORS Middleware Configuration ---
from fastapi.middleware.cors import CORSMiddleware

origins = [
    "http://localhost:3000",  # React development server
    "http://127.0.0.1:3000",
    # Add production origins as needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Include Phase 3 API Routers ---
app.include_router(monitoring_router)
app.include_router(security_router)

# --- Include Phase 4 Intelligent Monitoring Router ---
app.include_router(intelligent_monitoring_router)

# --- Connection Manager for WebSockets ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected: {websocket.client.host}:{websocket.client.port}, Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected: {websocket.client.host}:{websocket.client.port}, Total: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error sending message to {connection.client}: {e}")

    async def broadcast_json(self, data: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception as e:
                logger.error(f"Error sending JSON to {connection.client}: {e}")

manager = ConnectionManager()

# --- Redis Subscribers ---
async def metrics_subscriber(db_session_factory: sessionmaker, manager: ConnectionManager):
    logger.info(f"Connecting to Redis for metrics: {REDIS_URL}")
    try:
        r = await aioredis.from_url(REDIS_URL)
        pubsub = r.pubsub()
        await pubsub.subscribe(NETWORK_METRICS_CHANNEL)
        logger.info(f"Subscribed to Redis channel: {NETWORK_METRICS_CHANNEL}")

        while True:
            try:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    data_str = message["data"].decode("utf-8")
                    try:
                        metrics_data = PublishedInterfaceMetrics.model_validate_json(data_str)
                        logger.info(f"Received metrics: Interface {metrics_data.interface_name}, "
                                    f"Flows: {len(metrics_data.active_flows)}, "
                                    f"Pkts In/Out: {metrics_data.packets_in}/{metrics_data.packets_out}")
                        
                        db: Session = db_session_factory()
                        try:
                            db_metric = NetworkInterfaceMetric(
                                timestamp=datetime.fromtimestamp(metrics_data.timestamp, tz=datetime.timezone.utc),
                                interface_name=metrics_data.interface_name,
                                bytes_received=metrics_data.bytes_in,
                                bytes_sent=metrics_data.bytes_out,
                                packets_received=metrics_data.packets_in,
                                packets_sent=metrics_data.packets_out,
                            )
                            db.add(db_metric)
                            db.commit()
                            logger.debug(f"Stored interface metric for {metrics_data.interface_name}")

                            # Broadcast to WebSocket clients
                            bandwidth_payload = {
                                "timestamp": metrics_data.timestamp * 1000,
                                "upstreamBps": metrics_data.bytes_out * 8,
                                "downstreamBps": metrics_data.bytes_in * 8
                            }
                            await manager.broadcast_json({
                                "type": "BANDWIDTH_UPDATE",
                                "payload": bandwidth_payload
                            })
                        except Exception as db_exc:
                            logger.error(f"DB error storing metrics: {db_exc}")
                            db.rollback()
                        finally:
                            db.close()

                    except Exception as e:
                        logger.error(f"Error processing metrics JSON: {e} - Data: {data_str}")
                await asyncio.sleep(0.01)
            except (aioredis.ConnectionError, aioredis.TimeoutError) as e:
                logger.error(f"Redis connection error in metrics subscriber: {e}. Reconnecting...")
                await asyncio.sleep(5)
                try:
                    r = await aioredis.from_url(REDIS_URL)
                    pubsub = r.pubsub()
                    await pubsub.subscribe(NETWORK_METRICS_CHANNEL)
                    logger.info("Reconnected and re-subscribed to metrics channel.")
                except Exception as recon_e:
                    logger.error(f"Failed to reconnect to Redis for metrics: {recon_e}")
                    await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Unexpected error in metrics_subscriber: {e}")
                await asyncio.sleep(5)
    except Exception as e:
        logger.error(f"Could not connect to Redis for metrics subscription: {e}")

async def device_subscriber(db_session_factory: sessionmaker, manager: ConnectionManager):
    logger.info(f"Connecting to Redis for devices: {REDIS_URL}")
    try:
        r = await aioredis.from_url(REDIS_URL)
        pubsub = r.pubsub()
        await pubsub.subscribe(DEVICE_DISCOVERY_CHANNEL)
        logger.info(f"Subscribed to Redis channel: {DEVICE_DISCOVERY_CHANNEL}")

        while True:
            try:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    data_str = message["data"].decode("utf-8")
                    try:
                        device_data = PublishedDiscoveredDevice.model_validate_json(data_str)
                        logger.info(f"Received device: IP {device_data.ip_addr}, MAC {device_data.mac_addr}")
                        
                        db: Session = db_session_factory()
                        try:
                            db_device = db.query(Device).filter(Device.mac_address == device_data.mac_addr).first()
                            device_last_seen_dt = datetime.fromtimestamp(device_data.last_seen, tz=datetime.timezone.utc)
                            if db_device:
                                db_device.last_seen_timestamp = device_last_seen_dt
                                if db_device.ip_address != device_data.ip_addr:
                                    db_device.ip_address = device_data.ip_addr
                                    logger.info(f"Device MAC {device_data.mac_addr} IP updated to {device_data.ip_addr}")
                            else:
                                db_device = Device(
                                    ip_address=device_data.ip_addr,
                                    mac_address=device_data.mac_addr,
                                    first_seen_timestamp=device_last_seen_dt,
                                    last_seen_timestamp=device_last_seen_dt
                                )
                                db.add(db_device)
                            db.commit()
                            logger.debug(f"Upserted device: MAC {device_data.mac_addr}")
                            
                            device_payload_item = {
                                "id": db_device.mac_address,
                                "ipAddress": db_device.ip_address,
                                "macAddress": db_device.mac_address,
                                "name": getattr(db_device, 'name', db_device.ip_address),
                                "status": "online",
                                "firstSeen": db_device.first_seen_timestamp.isoformat() if db_device.first_seen_timestamp else None,
                                "lastSeen": db_device.last_seen_timestamp.isoformat() if db_device.last_seen_timestamp else None,
                            }
                            await manager.broadcast_json({
                                "type": "DEVICE_UPDATE",
                                "payload": [device_payload_item]
                            })
                        except Exception as db_exc:
                            logger.error(f"DB error storing device: {db_exc}")
                            db.rollback()
                        finally:
                            db.close()

                    except Exception as e:
                        logger.error(f"Error processing device JSON: {e} - Data: {data_str}")
                await asyncio.sleep(0.01)
            except (aioredis.ConnectionError, aioredis.TimeoutError) as e:
                logger.error(f"Redis connection error in device subscriber: {e}. Reconnecting...")
                await asyncio.sleep(5)
                try:
                    r = await aioredis.from_url(REDIS_URL)
                    pubsub = r.pubsub()
                    await pubsub.subscribe(DEVICE_DISCOVERY_CHANNEL)
                    logger.info("Reconnected and re-subscribed to device channel.")
                except Exception as recon_e:
                    logger.error(f"Failed to reconnect to Redis for devices: {recon_e}")
                    await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Unexpected error in device_subscriber: {e}")
                await asyncio.sleep(5)
    except Exception as e:
        logger.error(f"Could not connect to Redis for device subscription: {e}")

# --- Phase 3: Global FlowProcessor instance ---
flow_processor = None
flow_processor_task = None

# --- Application Lifecycle Events ---
@app.on_event("startup")
async def startup_event():
    global flow_processor, flow_processor_task
    logger.info("Starting Phase 4 Intelligent Network Monitoring API...")
    
    # Start traditional Redis subscribers
    logger.info("Starting Redis subscriber tasks...")
    asyncio.create_task(metrics_subscriber(SessionLocal, manager))
    asyncio.create_task(device_subscriber(SessionLocal, manager))
    
    # Start Phase 4 Enhanced FlowProcessor with Intelligent Monitoring
    logger.info("Starting Phase 4 Enhanced FlowProcessor with Intelligent Monitoring...")
    flow_processor = FlowProcessor(REDIS_URL)
    
    # Set the flow processor for the intelligent monitoring endpoints
    set_flow_processor(flow_processor)
    
    flow_processor_task = asyncio.create_task(flow_processor.start_processing())
    
    logger.info("Phase 4 Intelligent Network Monitoring API startup complete!")

@app.on_event("shutdown")
async def shutdown_event():
    global flow_processor, flow_processor_task
    logger.info("Shutting down Phase 4 Intelligent Network Monitoring API...")
    
    if flow_processor:
        logger.info("Stopping Enhanced FlowProcessor...")
        await flow_processor.stop_processing()
    if flow_processor_task:
        flow_processor_task.cancel()
        try:
            await flow_processor_task
        except asyncio.CancelledError:
            pass
    
    logger.info("Phase 4 Intelligent Network Monitoring API shutdown complete!")

# --- Root Endpoint ---
@app.get("/")
async def root():
    return {
        "message": "Welcome to the Intelligent Network Monitoring API - Phase 4",
        "version": "4.0.0",
        "features": [
            "Enhanced Flow Monitoring",
            "Security Detection (Port Scans, DDoS)",
            "ML Integration Framework",
            "Historical Data Analysis",
            "Real-time Alerts",
            "Intelligent Network Health Analysis",
            "Security-Performance Correlation",
            "Predictive Monitoring Insights",
            "Advanced Alerting with Context"
        ]
    }

# --- WebSocket Endpoint ---
@app.websocket("/ws/network-data")
async def websocket_endpoint(websocket: WebSocket, db: Session = Depends(get_db)):
    await manager.connect(websocket)
    try:
        # Send initial list of all devices to the newly connected client
        try:
            all_db_devices = db.query(Device).order_by(Device.last_seen_timestamp.desc()).all()
            initial_devices_payload = [
                {
                    "id": dev.mac_address,
                    "ipAddress": dev.ip_address,
                    "macAddress": dev.mac_address,
                    "name": getattr(dev, 'name', dev.ip_address),
                    "status": "online",
                    "firstSeen": dev.first_seen_timestamp.isoformat() if dev.first_seen_timestamp else None,
                    "lastSeen": dev.last_seen_timestamp.isoformat() if dev.last_seen_timestamp else None,
                } for dev in all_db_devices
            ]
            if initial_devices_payload:
                await websocket.send_json({"type": "ALL_DEVICES", "payload": initial_devices_payload})
                logger.info(f"Sent initial {len(initial_devices_payload)} devices to {websocket.client.host}:{websocket.client.port}")
            else:
                await websocket.send_json({"type": "ALL_DEVICES", "payload": []})
                logger.info(f"No initial devices to send to {websocket.client.host}:{websocket.client.port}")

        except Exception as e_init_devices:
            logger.error(f"Error sending initial device list to {websocket.client.host}: {e_init_devices}")

        # Keep the connection alive
        while True:
            try:
                await websocket.send_text(json.dumps({"type": "PING", "timestamp": datetime.utcnow().isoformat()}))
            except Exception:
                break
            await asyncio.sleep(30)

    except WebSocketDisconnect:
        logger.info(f"WebSocket cleanly disconnected by client: {websocket.client.host}:{websocket.client.port}")
    except Exception as e:
        logger.error(f"Error in websocket_endpoint for {websocket.client}: {e}")
    finally:
        manager.disconnect(websocket)

# --- Legacy API Endpoints (Compatibility) ---
@app.get("/api/v1/devices", response_model=List[PublishedDiscoveredDevice])
async def get_devices(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    devices = db.query(Device).offset(skip).limit(limit).all()
    return [
        PublishedDiscoveredDevice(
            ip_addr=device.ip_address,
            mac_addr=device.mac_address,
            last_seen=int(device.last_seen_timestamp.timestamp()),
            timestamp=int(device.last_seen_timestamp.timestamp())
        ) for device in devices
    ]

@app.get("/api/v1/metrics/interfaces/{interface_name}/latest", response_model=Optional[PublishedInterfaceMetrics])
async def get_latest_interface_metrics(interface_name: str, db: Session = Depends(get_db)):
    metric = db.query(NetworkInterfaceMetric)\
               .filter(NetworkInterfaceMetric.interface_name == interface_name)\
               .order_by(NetworkInterfaceMetric.timestamp.desc())\
               .first()
    if metric:
        return PublishedInterfaceMetrics(
            timestamp=int(metric.timestamp.timestamp()),
            interface_name=metric.interface_name,
            packets_in=metric.packets_received,
            packets_out=metric.packets_sent,
            bytes_in=metric.bytes_received,
            bytes_out=metric.bytes_sent,
            active_flows=[]
        )
    return None

@app.get("/api/v1/metrics/interfaces/{interface_name}/historical", response_model=List[PublishedInterfaceMetrics])
async def get_historical_interface_metrics(
    interface_name: str, 
    start_time: Optional[datetime] = None, 
    end_time: Optional[datetime] = None, 
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(NetworkInterfaceMetric)\
              .filter(NetworkInterfaceMetric.interface_name == interface_name)
    
    if start_time:
        query = query.filter(NetworkInterfaceMetric.timestamp >= start_time)
    if end_time:
        query = query.filter(NetworkInterfaceMetric.timestamp <= end_time)
        
    metrics = query.order_by(NetworkInterfaceMetric.timestamp.desc()).limit(limit).all()
    return [
        PublishedInterfaceMetrics(
            timestamp=int(m.timestamp.timestamp()),
            interface_name=m.interface_name,
            packets_in=m.packets_received,
            packets_out=m.packets_sent,
            bytes_in=m.bytes_received,
            bytes_out=m.bytes_sent,
            active_flows=[]
        ) for m in metrics
    ]

# --- Health Check Endpoint ---
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "connected",
            "redis": "connected",
            "flow_processor": "running" if flow_processor and flow_processor.is_processing else "stopped"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)