import React, { useEffect, useState } from "react";
import { Device, NetworkDataMessage } from "../../interfaces/networkData";
import { websocketService } from "../../services/websocketService";
import DeviceListItem from "./DeviceListItem";

const DeviceList: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const handleNewMessage = (data: NetworkDataMessage) => {
      if (data.type === "ALL_DEVICES") {
        setDevices(data.payload);
        setIsLoading(false);
      } else if (data.type === "DEVICE_UPDATE") {
        // More sophisticated update logic can be added here.
        // For now, let's assume DEVICE_UPDATE sends the full list or new devices to append.
        // A common pattern is to update existing devices or add new ones.
        setDevices((prevDevices) => {
          const updatedDevices = [...prevDevices];
          data.payload.forEach((newDevice) => {
            const existingDeviceIndex = updatedDevices.findIndex(
              (d) => d.id === newDevice.id,
            );
            if (existingDeviceIndex !== -1) {
              updatedDevices[existingDeviceIndex] = newDevice;
            } else {
              updatedDevices.push(newDevice);
            }
          });
          // Sort devices, e.g., by IP address or status
          updatedDevices.sort((a, b) =>
            a.ipAddress.localeCompare(b.ipAddress),
          );
          return updatedDevices;
        });
        setIsLoading(false);
      }
    };

    websocketService.addMessageListener(handleNewMessage);
    // Assuming connect is called elsewhere or if not, call it here.
    // For this component, let's assume connection is managed globally or by a parent.
    // If this component is responsible for initiating, then:
    // websocketService.connect();

    // Request initial device list if needed (backend specific)
    // websocketService.sendMessage({ type: "GET_ALL_DEVICES" });


    return () => {
      websocketService.removeMessageListener(handleNewMessage);
      // Optional: disconnect if this component was responsible for connecting
      // websocketService.disconnect();
    };
  }, []);

  if (isLoading && devices.length === 0) {
    return (
      <div className="text-center p-10">
        <p className="text-gray-500 text-lg">Loading devices...</p>
      </div>
    );
  }

  if (!isLoading && devices.length === 0) {
    return (
      <div className="text-center p-10">
        <p className="text-gray-500 text-lg">No devices detected.</p>
      </div>
    );
  }

  return (
    <div className="container mx-auto">
      <h2 className="text-2xl font-semibold text-gray-700 mb-6">
        Connected Devices
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {devices.map((device) => (
          <DeviceListItem key={device.id} device={device} />
        ))}
      </div>
    </div>
  );
};

export default DeviceList;