from sqlalchemy import (
    Column,
    Integer,
    String,
    BigInteger,
    DateTime,
    Float,
    Boolean,
    Interval,
    TEXT,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.sql import func  # For current_timestamp

from .database import Base


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    mac_address = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=True)
    first_seen_timestamp = Column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class NetworkInterfaceMetric(Base):
    __tablename__ = "network_interface_metrics"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    interface_name = Column(String, index=True, nullable=False)
    bytes_received = Column(BigInteger, nullable=False)
    bytes_sent = Column(BigInteger, nullable=False)
    packets_received = Column(BigInteger, nullable=False)
    packets_sent = Column(BigInteger, nullable=False)
    # We could add a UniqueConstraint for (timestamp, interface_name) if needed


class BandwidthHistory(Base):
    __tablename__ = "bandwidth_history"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    total_bytes_per_sec = Column(Float, nullable=False)
    total_packets_per_sec = Column(Float, nullable=False)
    peak_bandwidth = Column(Float, nullable=False)
    average_bandwidth = Column(Float, nullable=False)
    active_flows = Column(Integer, nullable=False)


class TopTalkersHistory(Base):
    __tablename__ = "top_talkers_history"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True) # INET mapped to String
    bytes_total = Column(BigInteger, nullable=False)
    packets_total = Column(BigInteger, nullable=False)
    flows_count = Column(Integer, nullable=False)
    protocols = Column(ARRAY(TEXT), nullable=True) # TEXT[] mapped to ARRAY(TEXT)
    rank_by_bytes = Column(Integer, nullable=False)
    rank_by_packets = Column(Integer, nullable=False)


class ProtocolDistributionHistory(Base):
    __tablename__ = "protocol_distribution_history"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    protocol_number = Column(Integer, nullable=False)
    protocol_name = Column(String(50), nullable=True)
    flows_count = Column(Integer, nullable=False)
    bytes_total = Column(BigInteger, nullable=False)
    packets_total = Column(BigInteger, nullable=False)
    percentage = Column(Float, nullable=False)


class NetworkFlow(Base): # Renamed to avoid conflict if there's a Pydantic model named NetworkFlow
    __tablename__ = "network_flows"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    src_ip = Column(String, nullable=False, index=True) # INET
    dst_ip = Column(String, nullable=False, index=True) # INET
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False, index=True)
    protocol = Column(Integer, nullable=False)
    duration = Column(Interval, nullable=False)
    packets_sent = Column(BigInteger, nullable=False)
    packets_received = Column(BigInteger, nullable=False)
    bytes_sent = Column(BigInteger, nullable=False)
    bytes_received = Column(BigInteger, nullable=False)
    avg_packet_size = Column(Float, nullable=True)
    packets_per_second = Column(Float, nullable=True)
    bytes_per_second = Column(Float, nullable=True)
    connection_state = Column(String(20), nullable=True)
    is_suspicious = Column(Boolean, default=False, index=True)
    threat_indicators = Column(ARRAY(TEXT), nullable=True) # TEXT[]
    ml_confidence_score = Column(Float, nullable=True)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    source_ip = Column(String, nullable=True) # INET
    target_ip = Column(String, nullable=True) # INET
    target_port = Column(Integer, nullable=True)
    description = Column(TEXT, nullable=False)
    details = Column(JSONB, nullable=True)
    confidence_score = Column(Float, nullable=True)
    is_acknowledged = Column(Boolean, default=False, index=True)
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)