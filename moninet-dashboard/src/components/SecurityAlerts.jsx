// src/components/SecurityAlerts.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, Shield, Eye, EyeOff, CheckCircle, XCircle, Filter, ChevronDown, ChevronUp, RefreshCw } from 'lucide-react';

const SecurityAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('all'); // all, critical, high, medium, low
  const [filterAcknowledged, setFilterAcknowledged] = useState('all'); // all, yes, no
  const [sortBy, setSortBy] = useState('timestamp'); // timestamp, severity, type
  const [sortOrder, setSortOrder] = useState('desc'); // asc, desc
  const [showDetails, setShowDetails] = useState({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAlerts = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Construct query parameters based on filters
      const params = new URLSearchParams();
      if (filterSeverity !== 'all') params.append('severity', filterSeverity);
      if (filterAcknowledged !== 'all') params.append('acknowledged', filterAcknowledged === 'yes' ? 'true' : 'false');
      params.append('sort_by', sortBy);
      params.append('sort_order', sortOrder);
      
      const response = await fetch(`/api/security/alerts?${params.toString()}`);
      if (!response.ok) {
        const errData = await response.json().catch(() => ({detail: "Unknown error"}));
        throw new Error(`HTTP error! status: ${response.status} - ${errData.detail}`);
      }
      const data = await response.json();
      setAlerts(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
      setError(error.message);
      setAlerts([]);
    } finally {
      setIsLoading(false);
    }
  }, [filterSeverity, filterAcknowledged, sortBy, sortOrder]);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  const handleAcknowledgeAlert = async (alertId) => {
    try {
      const response = await fetch(`/api/security/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Assuming backend can identify user or pass a generic one
        body: JSON.stringify({ acknowledged_by: 'dashboard_user' }) 
      });
      if (!response.ok) throw new Error('Failed to acknowledge alert');
      fetchAlerts(); // Refresh alerts
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
      // Potentially show user feedback
    }
  };

  const handleDismissAlert = async (alertId) => {
    // This might be a DELETE or a state change like 'is_dismissed'
    // Assuming DELETE for now as per plan
    if (window.confirm("Are you sure you want to dismiss this alert? This action might be permanent.")) {
        try {
          const response = await fetch(`/api/security/alerts/${alertId}`, { method: 'DELETE' });
          if (!response.ok) throw new Error('Failed to dismiss alert');
          fetchAlerts(); // Refresh alerts
        } catch (error) {
          console.error('Failed to dismiss alert:', error);
        }
    }
  };

  const toggleDetails = (alertId) => {
    setShowDetails(prev => ({ ...prev, [alertId]: !prev[alertId] }));
  };

  const getSeverityClassNames = (severity) => {
    const base = "px-2 py-0.5 text-xs font-semibold rounded-full border";
    const colors = {
      critical: `${base} bg-red-100 text-red-700 border-red-300`,
      high: `${base} bg-orange-100 text-orange-700 border-orange-300`,
      medium: `${base} bg-yellow-100 text-yellow-700 border-yellow-300`,
      low: `${base} bg-blue-100 text-blue-700 border-blue-300`,
      info: `${base} bg-gray-100 text-gray-700 border-gray-300`,
    };
    return colors[severity.toLowerCase()] || colors.info;
  };
  
  const getAlertIcon = (alertType) => {
    const icons = {
      port_scan: Shield,
      ddos: AlertTriangle,
      ml_detection: Eye, // Or a more specific ML icon
      suspicious_traffic: AlertTriangle, // Generic
      volumetric_attack: AlertTriangle, // Specific DDoS type
    };
    const IconComponent = icons[alertType.toLowerCase()] || AlertTriangle;
    return <IconComponent className="w-5 h-5" />;
  };

  const handleSort = (column) => {
    if (sortBy === column) {
      setSortOrder(prevOrder => prevOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
  };

  const SortIndicator = ({ column }) => {
    if (sortBy !== column) return null;
    return sortOrder === 'asc' ? <ChevronUp className="w-3 h-3 ml-1" /> : <ChevronDown className="w-3 h-3 ml-1" />;
  };
  
  const unacknowledgedCount = alerts.filter(a => !a.is_acknowledged).length;

  return (
    <div className="p-4 md:p-6 space-y-6 bg-gray-50 min-h-screen">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
        <h2 className="text-2xl font-semibold text-gray-700 flex items-center">
          <Shield className="w-7 h-7 mr-2 text-blue-600" />
          Security Alerts
          {unacknowledgedCount > 0 && (
            <span className="ml-3 bg-red-500 text-white text-xs font-bold px-2 py-1 rounded-full">
              {unacknowledgedCount} New
            </span>
          )}
        </h2>
        <button onClick={fetchAlerts} disabled={isLoading} className="p-2 text-gray-500 hover:text-blue-600 disabled:text-gray-300 transition-colors rounded-full hover:bg-gray-100">
            <RefreshCw className={`w-5 h-5 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Filters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 mb-4 p-4 bg-white rounded-lg shadow">
        <div>
          <label htmlFor="filterSeverity" className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
          <select id="filterSeverity" value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}
            className="w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 text-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option> <option value="high">High</option>
            <option value="medium">Medium</option> <option value="low">Low</option>
          </select>
        </div>
        <div>
          <label htmlFor="filterAcknowledged" className="block text-sm font-medium text-gray-700 mb-1">Status</label>
          <select id="filterAcknowledged" value={filterAcknowledged} onChange={(e) => setFilterAcknowledged(e.target.value)}
            className="w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 text-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
            <option value="all">All</option> <option value="no">Unacknowledged</option> <option value="yes">Acknowledged</option>
          </select>
        </div>
        <div>
          <label htmlFor="sortBy" className="block text-sm font-medium text-gray-700 mb-1">Sort By</label>
          <select id="sortBy" value={sortBy} onChange={(e) => handleSort(e.target.value)}
            className="w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 text-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
            <option value="timestamp">Time</option> <option value="severity">Severity</option> <option value="alert_type">Type</option>
          </select>
        </div>
         <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Order</label>
            <button onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
                className="w-full flex items-center justify-center border border-gray-300 rounded-md shadow-sm px-3 py-2 text-sm bg-white hover:bg-gray-50 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                {sortOrder === 'asc' ? 'Ascending' : 'Descending'}
                {sortOrder === 'asc' ? <ChevronUp className="w-4 h-4 ml-2" /> : <ChevronDown className="w-4 h-4 ml-2" />}
            </button>
        </div>
      </div>
      
      {isLoading && <div className="text-center py-10 text-gray-500">Loading alerts...</div>}
      {error && <div className="text-center py-10 text-red-500 bg-red-50 p-4 rounded-md">Error fetching alerts: {error}</div>}
      
      {!isLoading && !error && alerts.length === 0 && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-6 text-center shadow">
          <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
          <h3 className="text-lg font-medium text-green-800">No Security Alerts</h3>
          <p className="text-sm text-green-600">Your network appears to be secure based on current filters.</p>
        </div>
      )}

      {!isLoading && !error && alerts.length > 0 && (
        <div className="space-y-3">
          {alerts.map(alert => (
            <div key={alert.id} className={`bg-white border rounded-lg shadow-sm p-4 transition-opacity duration-300 ${alert.is_acknowledged ? 'opacity-70 border-gray-200' : 'border-l-4 ' + (getSeverityClassNames(alert.severity).split(' ')[2] || 'border-blue-500')}`}>
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3 flex-1 min-w-0">
                  <div className={`p-1.5 rounded-full ${getSeverityClassNames(alert.severity).split(' ')[0]} ${getSeverityClassNames(alert.severity).split(' ')[1]}`}>
                    {getAlertIcon(alert.alert_type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-1">
                      <span className={getSeverityClassNames(alert.severity)}>{alert.severity.toUpperCase()}</span>
                      <span className="text-xs text-gray-500 bg-gray-100 px-1.5 py-0.5 rounded font-medium">{alert.alert_type.replace(/_/g, ' ').toUpperCase()}</span>
                      <span className="text-xs text-gray-500"><Clock className="w-3 h-3 inline mr-1" />{new Date(alert.timestamp).toLocaleString()}</span>
                    </div>
                    <h3 className="font-medium text-gray-800 text-sm sm:text-base break-words">{alert.description}</h3>
                    <div className="text-xs text-gray-600 mt-1 space-y-0.5">
                      {alert.source_ip && <div>Source: <span className="font-mono bg-gray-100 px-1 rounded">{alert.source_ip}</span></div>}
                      {alert.target_ip && <div>Target: <span className="font-mono bg-gray-100 px-1 rounded">{alert.target_ip}{alert.target_port ? `:${alert.target_port}` : ''}</span></div>}
                      {typeof alert.confidence_score === 'number' && <div>Confidence: <span className="font-semibold">{(alert.confidence_score * 100).toFixed(0)}%</span></div>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-1 sm:space-x-2 ml-2 flex-shrink-0">
                  <button onClick={() => toggleDetails(alert.id)} className="p-1.5 text-gray-400 hover:text-blue-600 rounded-full hover:bg-gray-100" title={showDetails[alert.id] ? "Hide Details" : "Show Details"}>
                    {showDetails[alert.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                  {!alert.is_acknowledged && (
                    <button onClick={() => handleAcknowledgeAlert(alert.id)} className="p-1.5 text-green-500 hover:text-green-700 rounded-full hover:bg-green-50" title="Acknowledge">
                      <CheckCircle className="w-4 h-4" />
                    </button>
                  )}
                  <button onClick={() => handleDismissAlert(alert.id)} className="p-1.5 text-red-500 hover:text-red-700 rounded-full hover:bg-red-50" title="Dismiss Alert">
                    <XCircle className="w-4 h-4" />
                  </button>
                </div>
              </div>
              {showDetails[alert.id] && (
                <div className="mt-3 pt-3 border-t border-gray-200">
                  <h4 className="text-xs font-semibold text-gray-700 mb-1.5">ALERT DETAILS:</h4>
                  <pre className="text-xs text-gray-600 bg-gray-50 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">
                    {JSON.stringify(alert.details || {info: "No additional details."}, null, 2)}
                  </pre>
                </div>
              )}
              {alert.is_acknowledged && (
                <div className="mt-2 pt-2 border-t border-gray-100 flex items-center text-xs text-gray-500">
                  <CheckCircle className="w-3.5 h-3.5 mr-1.5 text-green-500" />
                  Acknowledged by {alert.acknowledged_by || 'system'} at {alert.acknowledged_at ? new Date(alert.acknowledged_at).toLocaleString() : 'N/A'}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SecurityAlerts;