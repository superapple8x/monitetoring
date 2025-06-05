-- migrations/003_enhanced_monitoring.sql

-- Historical bandwidth data
CREATE TABLE IF NOT EXISTS bandwidth_history (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    total_bytes_per_sec DOUBLE PRECISION NOT NULL,
    total_packets_per_sec DOUBLE PRECISION NOT NULL,
    peak_bandwidth DOUBLE PRECISION NOT NULL,
    average_bandwidth DOUBLE PRECISION NOT NULL,
    active_flows INTEGER NOT NULL
);

-- Create index for time-series queries
CREATE INDEX IF NOT EXISTS idx_bandwidth_history_timestamp ON bandwidth_history(timestamp);

-- Top talkers history
CREATE TABLE IF NOT EXISTS top_talkers_history (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address INET NOT NULL,
    bytes_total BIGINT NOT NULL,
    packets_total BIGINT NOT NULL,
    flows_count INTEGER NOT NULL,
    protocols TEXT[], -- Array of protocol numbers
    rank_by_bytes INTEGER NOT NULL,
    rank_by_packets INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_top_talkers_timestamp ON top_talkers_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_top_talkers_ip ON top_talkers_history(ip_address);

-- Protocol distribution history
CREATE TABLE IF NOT EXISTS protocol_distribution_history (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    protocol_number INTEGER NOT NULL,
    protocol_name VARCHAR(50), -- TCP, UDP, ICMP, etc.
    flows_count INTEGER NOT NULL,
    bytes_total BIGINT NOT NULL,
    packets_total BIGINT NOT NULL,
    percentage DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_protocol_history_timestamp ON protocol_distribution_history(timestamp);

-- Flow details table for security analysis
CREATE TABLE IF NOT EXISTS network_flows (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    duration INTERVAL NOT NULL,
    packets_sent BIGINT NOT NULL,
    packets_received BIGINT NOT NULL,
    bytes_sent BIGINT NOT NULL,
    bytes_received BIGINT NOT NULL,
    avg_packet_size DOUBLE PRECISION,
    packets_per_second DOUBLE PRECISION,
    bytes_per_second DOUBLE PRECISION,
    connection_state VARCHAR(20),
    -- Security-relevant fields
    is_suspicious BOOLEAN DEFAULT FALSE,
    threat_indicators TEXT[], -- Array of detected threats
    ml_confidence_score DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON network_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_port ON network_flows(dst_port);
CREATE INDEX IF NOT EXISTS idx_flows_suspicious ON network_flows(is_suspicious);

-- Security alerts table
CREATE TABLE IF NOT EXISTS security_alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    alert_type VARCHAR(50) NOT NULL, -- 'port_scan', 'ddos', 'ml_anomaly'
    severity VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    source_ip INET,
    target_ip INET,
    target_port INTEGER,
    description TEXT NOT NULL,
    details JSONB, -- Flexible storage for alert-specific data
    confidence_score DOUBLE PRECISION,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON security_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON security_alerts(is_acknowledged);