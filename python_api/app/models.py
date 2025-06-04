from sqlalchemy import Column, Integer, String, BigInteger, DateTime
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