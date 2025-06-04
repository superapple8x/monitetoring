export interface Device {
  id: string;
  ipAddress: string;
  macAddress?: string;
  name?: string;
  status: "online" | "offline";
  firstSeen: string; // ISO 8601 date string
  lastSeen: string; // ISO 8601 date string
}

export interface BandwidthStats {
  timestamp: number; // Unix timestamp (ms)
  upstreamBps: number; // Bits per second
  downstreamBps: number; // Bits per second
}

export interface ConnectivityStatus {
  serviceStatus: "connected" | "disconnected" | "error" | "connecting";
  gatewayPingMs?: number;
  lastMessageTimestamp?: number; // Unix timestamp (ms)
}

// Combined type for messages from WebSocket, can be extended
export type NetworkDataMessage =
  | { type: "DEVICE_UPDATE"; payload: Device[] }
  | { type: "BANDWIDTH_UPDATE"; payload: BandwidthStats }
  | { type: "CONNECTIVITY_UPDATE"; payload: ConnectivityStatus }
  | { type: "ALL_DEVICES"; payload: Device[] }; // Initial dump of all devices