import React, { useEffect } from "react";
import DashboardLayout from "./components/Layout/DashboardLayout";
import DeviceList from "./components/DeviceList/DeviceList";
import BandwidthUsage from "./components/BandwidthUsage/BandwidthUsage";
import ConnectivityStatus from "./components/ConnectivityStatus/ConnectivityStatus";
import HistoricalCharts from "./components/HistoricalCharts"; // Added import
import SecurityAlerts from "./components/SecurityAlerts"; // Added import
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
        <SecurityAlerts />
        <HistoricalCharts />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6"> {/* Grouping older components */}
          <ConnectivityStatus />
          <BandwidthUsage />
        </div>
        <DeviceList />
      </div>
    </DashboardLayout>
  );
}

export default App;
