import React, { useEffect, useState } from "react";
import {
  ConnectivityStatus as ConnectivityStatusInterface,
  NetworkDataMessage,
} from "../../interfaces/networkData";
import { websocketService } from "../../services/websocketService";

const ConnectivityStatus: React.FC = () => {
  const [status, setStatus] = useState<ConnectivityStatusInterface>({
    serviceStatus: "connecting", // Initial state
  });

  useEffect(() => {
    const handleNewMessage = (data: NetworkDataMessage) => {
      if (data.type === "CONNECTIVITY_UPDATE") {
        setStatus(data.payload);
      }
    };

    websocketService.addMessageListener(handleNewMessage);

    // The websocketService now sends an initial CONNECTIVITY_UPDATE on open/close/error
    // No need for explicit GET_CONNECTIVITY_STATUS or timeout logic here.

    return () => {
      websocketService.removeMessageListener(handleNewMessage);
    };
  }, []); // Empty dependency array, runs once on mount

  let statusText = "Connecting...";
  let bgColor = "bg-blue-100"; // Default to connecting color
  let textColor = "text-blue-700";
  let pingText = "";

  switch (status.serviceStatus) {
    case "connected":
      statusText = "Connected to Monitoring Service";
      bgColor = "bg-green-100";
      textColor = "text-green-700";
      if (status.gatewayPingMs !== undefined) {
        pingText = `Gateway Ping: ${status.gatewayPingMs} ms`;
      }
      break;
    case "disconnected":
      statusText = "Disconnected from Monitoring Service";
      bgColor = "bg-red-100";
      textColor = "text-red-700";
      break;
    case "error":
      statusText = "Error Connecting / Connection Lost";
      bgColor = "bg-red-100";
      textColor = "text-red-700";
      break;
    case "connecting":
      statusText = "Connecting to Monitoring Service...";
      bgColor = "bg-blue-100";
      textColor = "text-blue-700";
      break;
    default:
      statusText = "Unknown status";
      bgColor = "bg-gray-100";
      textColor = "text-gray-700";
  }

  return (
    <div className={`p-4 rounded-lg shadow-md ${bgColor} ${textColor}`}>
      <h2 className="text-lg font-semibold mb-2">System Status</h2>
      <p>{statusText}</p>
      {pingText && <p className="text-sm mt-1">{pingText}</p>}
      {status?.lastMessageTimestamp && (
        <p className="text-xs text-gray-500 mt-1">
          Last update: {new Date(status.lastMessageTimestamp).toLocaleTimeString()}
        </p>
      )}
    </div>
  );
};

export default ConnectivityStatus;