import React from "react";
import { Device } from "../../interfaces/networkData";

interface DeviceListItemProps {
  device: Device;
}

const DeviceListItem: React.FC<DeviceListItemProps> = ({ device }) => {
  const statusColor = device.status === "online" ? "bg-green-500" : "bg-red-500";
  const lastSeenDate = new Date(device.lastSeen).toLocaleString();

  return (
    <div className="bg-white shadow-md rounded-lg p-4 mb-4 hover:shadow-lg transition-shadow duration-200">
      <div className="flex justify-between items-center mb-2">
        <h3 className="text-lg font-semibold text-gray-800">
          {device.name || device.ipAddress}
        </h3>
        <span
          className={`px-2 py-1 text-xs font-semibold text-white rounded-full ${statusColor}`}
        >
          {device.status.toUpperCase()}
        </span>
      </div>
      <div className="text-sm text-gray-600">
        <p>
          <strong>IP Address:</strong> {device.ipAddress}
        </p>
        {device.macAddress && (
          <p>
            <strong>MAC Address:</strong> {device.macAddress}
          </p>
        )}
        <p>
          <strong>Last Seen:</strong> {lastSeenDate}
        </p>
      </div>
    </div>
  );
};

export default DeviceListItem;