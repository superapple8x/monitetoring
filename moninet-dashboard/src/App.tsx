import React, { useEffect } from "react";
import DashboardLayout from "./components/Layout/DashboardLayout";
import DeviceList from "./components/DeviceList/DeviceList";
import BandwidthUsage from "./components/BandwidthUsage/BandwidthUsage";
import ConnectivityStatus from "./components/ConnectivityStatus/ConnectivityStatus";
import { websocketService } from "./services/websocketService";

function App() {
  useEffect(() => {
    // Connect to WebSocket when the App component mounts, with a slight delay
    const timerId = setTimeout(() => {
      websocketService.connect();
    }, 1000); // 1-second delay

    // Optional: Disconnect when the App component unmounts
    return () => {
      clearTimeout(timerId);
      websocketService.disconnect();
    };
  }, []); // Empty dependency array ensures this runs only once on mount/unmount

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <ConnectivityStatus />
        <BandwidthUsage />
        <DeviceList />
      </div>
    </DashboardLayout>
  );
}

export default App;
