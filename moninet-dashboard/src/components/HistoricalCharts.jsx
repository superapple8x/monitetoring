// src/components/HistoricalCharts.jsx
import React, { useState, useEffect } from 'react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  TimeScale, // Import TimeScale for time-based x-axis
} from 'chart.js';
import 'chartjs-adapter-date-fns'; // Import the date adapter

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  TimeScale // Register TimeScale
);

const HistoricalCharts = () => {
  const [bandwidthData, setBandwidthData] = useState(null);
  const [protocolData, setProtocolData] = useState(null);
  const [topTalkersData, setTopTalkersData] = useState(null);
  const [timeRange, setTimeRange] = useState('1h'); // 1h, 6h, 24h, 7d
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchHistoricalData = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const response = await fetch(`/api/monitoring/historical?range=${timeRange}`);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        setBandwidthData(processBandwidthData(data.bandwidth_history));
        setProtocolData(processProtocolData(data.protocol_distribution_history)); // Corrected key
        setTopTalkersData(processTopTalkersData(data.top_talkers_history)); // Corrected key
      } catch (error) {
        console.error('Failed to fetch historical data:', error);
        setError(error.message);
        setBandwidthData(null);
        setProtocolData(null);
        setTopTalkersData(null);
      } finally {
        setIsLoading(false);
      }
    };

    fetchHistoricalData();
    const interval = setInterval(fetchHistoricalData, 60000); // Update every minute
    return () => clearInterval(interval);
  }, [timeRange]);

  const processBandwidthData = (history) => {
    if (!history || history.length === 0) return null;

    const labels = history.map(item => new Date(item.timestamp));
    
    return {
      labels,
      datasets: [
        {
          label: 'Avg Bandwidth (MB/s)',
          data: history.map(item => (item.average_bandwidth / 1024 / 1024).toFixed(3)),
          borderColor: 'rgb(59, 130, 246)',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          fill: true,
          tension: 0.3,
        },
        {
          label: 'Peak Bandwidth (MB/s)',
          data: history.map(item => (item.peak_bandwidth / 1024 / 1024).toFixed(3)),
          borderColor: 'rgb(239, 68, 68)',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: false,
          borderDash: [5, 5],
          tension: 0.3,
        }
      ]
    };
  };

  const processProtocolData = (history) => {
    // Use the latest entry in history for protocol distribution
    if (!history || history.length === 0) return null;
    const latestEntry = history[history.length - 1]; // Assuming history is sorted by time
    
    // The structure from the plan was: data.protocol_distribution which is a Vec<ProtocolStats>
    // If `latestEntry` is directly the Vec<ProtocolStats> for the latest timestamp:
    const protocolStatsArray = latestEntry.protocol_stats || latestEntry; // Adjust if nested

    if (!Array.isArray(protocolStatsArray) || protocolStatsArray.length === 0) return null;


    const protocolNames = {
      1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP',
      // Add more as needed
    };
    
    return {
      labels: protocolStatsArray.map(item => 
        protocolNames[item.protocol_number] || `Proto ${item.protocol_number}`
      ),
      datasets: [{
        data: protocolStatsArray.map(item => item.percentage.toFixed(1)),
        backgroundColor: [
          'rgba(59, 130, 246, 0.7)', 'rgba(16, 185, 129, 0.7)',
          'rgba(245, 158, 11, 0.7)', 'rgba(239, 68, 68, 0.7)',
          'rgba(139, 92, 246, 0.7)', 'rgba(236, 72, 153, 0.7)',
          'rgba(22, 163, 74, 0.7)', 'rgba(217, 119, 6, 0.7)'
        ],
        borderColor: '#fff',
        borderWidth: 1
      }]
    };
  };

  const processTopTalkersData = (history) => {
    // Use the latest entry in history for top talkers
    if (!history || history.length === 0) return null;
    const latestEntry = history[history.length - 1]; // Assuming history is sorted
    
    // The structure from the plan was: data.top_talkers which is a Vec<TopTalker>
    // If `latestEntry` is directly the Vec<TopTalker> for the latest timestamp:
    const topTalkersArray = latestEntry.talkers || latestEntry; // Adjust if nested

    if (!Array.isArray(topTalkersArray) || topTalkersArray.length === 0) return null;

    // Sort by bytes_total descending and take top 10
    const sortedTalkers = [...topTalkersArray]
        .sort((a,b) => b.bytes_total - a.bytes_total)
        .slice(0,10);

    return {
      labels: sortedTalkers.map(item => item.ip_address),
      datasets: [{
        label: 'Total Bytes (MB)',
        data: sortedTalkers.map(item => (item.bytes_total / 1024 / 1024).toFixed(2)),
        backgroundColor: 'rgba(16, 185, 129, 0.7)',
        borderColor: 'rgb(16, 185, 129)',
        borderWidth: 1
      }]
    };
  };

  const commonChartOptions = (titleText) => ({
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top', labels: { color: '#4A5568' } },
      title: { display: true, text: titleText, font: { size: 16 }, color: '#2D3748' },
      tooltip: { mode: 'index', intersect: false, bodySpacing: 4, titleSpacing: 6 }
    },
    scales: {
      x: {
        type: 'time', // Use time scale
        time: { unit: timeRange === '7d' ? 'day' : (timeRange === '24h' ? 'hour' : 'minute') },
        ticks: { color: '#718096', maxRotation: 0, autoSkip: true, autoSkipPadding: 15 },
        grid: { display: false },
        title: { display: true, text: 'Time', color: '#4A5568' }
      },
      y: {
        ticks: { color: '#718096', callback: function(value) { return value + ' MB/s';} }, // Example for bandwidth
        grid: { color: '#E2E8F0' },
        title: { display: true, text: 'Bandwidth (MB/s)', color: '#4A5568' }
      }
    },
    interaction: { mode: 'nearest', axis: 'x', intersect: false }
  });
  
  const barChartOptions = (yAxisTitle, xAxisTitle) => ({
    ...commonChartOptions(yAxisTitle), // Reuse common options but override scales
    indexAxis: 'y', // For horizontal bar chart
    scales: {
      x: {
        ticks: { color: '#718096', callback: function(value) { return value + ' MB';} },
        grid: { color: '#E2E8F0' },
        title: { display: true, text: xAxisTitle, color: '#4A5568' }
      },
      y: {
        ticks: { color: '#718096' },
        grid: { display: false },
        title: { display: true, text: 'IP Address', color: '#4A5568' }
      }
    }
  });


  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'right', labels: { color: '#4A5568', boxWidth: 15, padding: 15 } },
      title: { display: true, text: 'Protocol Distribution (Latest Snapshot)', font: {size: 16}, color: '#2D3748'},
      tooltip: {
        callbacks: {
          label: function(context) {
            let label = context.label || '';
            if (label) { label += ': '; }
            if (context.parsed !== null) { label += context.parsed.toFixed(1) + '%'; }
            return label;
          }
        }
      }
    }
  };
  
  const renderLoadingOrError = (chartName) => {
    if (isLoading) return <div className="flex items-center justify-center h-full text-gray-500">Loading {chartName} data...</div>;
    if (error) return <div className="flex items-center justify-center h-full text-red-500">Error loading data: {error}</div>;
    return null;
  }


  return (
    <div className="p-4 md:p-6 space-y-6 bg-gray-50 min-h-screen">
      <div className="flex flex-col sm:flex-row justify-between items-center mb-6">
        <h2 className="text-2xl font-semibold text-gray-700">Network Analytics</h2>
        <div className="flex space-x-1 sm:space-x-2 mt-2 sm:mt-0">
          {['1h', '6h', '24h', '7d'].map(range => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-blue-500 ${
                timeRange === range
                  ? 'bg-blue-600 text-white shadow-sm hover:bg-blue-700'
                  : 'bg-white text-gray-600 border border-gray-300 hover:bg-gray-100'
              }`}
            >
              {range.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-lg p-4 sm:p-6">
        <div className="h-72 sm:h-80">
          {bandwidthData ? (
            <Line data={bandwidthData} options={commonChartOptions('Bandwidth Usage Over Time')} />
          ) : (
            renderLoadingOrError('Bandwidth')
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl shadow-lg p-4 sm:p-6">
          <div className="h-72 sm:h-80">
            {protocolData ? (
              <Doughnut data={protocolData} options={doughnutOptions} />
            ) : (
              renderLoadingOrError('Protocol Distribution')
            )}
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-lg p-4 sm:p-6">
          <div className="h-72 sm:h-80">
            {topTalkersData ? (
              <Bar 
                data={topTalkersData} 
                options={barChartOptions('Top Bandwidth Consumers (Latest Snapshot)', 'Total Bytes (MB)')} 
              />
            ) : (
              renderLoadingOrError('Top Talkers')
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default HistoricalCharts;