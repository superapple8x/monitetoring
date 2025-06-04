import React, { useEffect, useState } from "react";
import {
  BandwidthStats,
  NetworkDataMessage,
} from "../../interfaces/networkData";
import { websocketService } from "../../services/websocketService";

const formatBps = (bps: number): string => {
  if (bps < 1000) {
    return `${bps.toFixed(0)} bps`;
  } else if (bps < 1000 * 1000) {
    return `${(bps / 1000).toFixed(2)} Kbps`;
  } else if (bps < 1000 * 1000 * 1000) {
    return `${(bps / (1000 * 1000)).toFixed(2)} Mbps`;
  } else {
    return `${(bps / (1000 * 1000 * 1000)).toFixed(2)} Gbps`;
  }
};

const BandwidthUsage: React.FC = () => {
  const [bandwidth, setBandwidth] = useState<BandwidthStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const handleNewMessage = (data: NetworkDataMessage) => {
      if (data.type === "BANDWIDTH_UPDATE") {
        setBandwidth(data.payload);
        setIsLoading(false);
      }
    };

    websocketService.addMessageListener(handleNewMessage);
    // Assuming connect is managed globally or by a parent component.
    // If this component needs to trigger a fetch for initial data:
    // websocketService.sendMessage({ type: "GET_BANDWIDTH_STATS" });


    return () => {
      websocketService.removeMessageListener(handleNewMessage);
    };
  }, []);

  if (isLoading && !bandwidth) {
    return (
      <div className="bg-white shadow-md rounded-lg p-6 text-center">
        <p className="text-gray-500">Loading bandwidth data...</p>
      </div>
    );
  }

  if (!bandwidth) {
    return (
      <div className="bg-white shadow-md rounded-lg p-6 text-center">
        <p className="text-gray-500">No bandwidth data available.</p>
      </div>
    );
  }

  return (
    <div className="bg-white shadow-md rounded-lg p-6">
      <h2 className="text-xl font-semibold text-gray-700 mb-4">
        Live Bandwidth Usage
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-center">
        <div className="p-4 bg-blue-50 rounded-lg">
          <p className="text-sm text-blue-500 font-medium">UPLOAD</p>
          <p className="text-2xl font-bold text-blue-700">
            {formatBps(bandwidth.upstreamBps)}
          </p>
        </div>
        <div className="p-4 bg-green-50 rounded-lg">
          <p className="text-sm text-green-500 font-medium">DOWNLOAD</p>
          <p className="text-2xl font-bold text-green-700">
            {formatBps(bandwidth.downstreamBps)}
          </p>
        </div>
      </div>
      <p className="text-xs text-gray-400 mt-4 text-center">
        Last updated: {new Date(bandwidth.timestamp).toLocaleTimeString()}
      </p>
    </div>
  );
};

export default BandwidthUsage;