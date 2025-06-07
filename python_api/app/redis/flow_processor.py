# src/redis/flow_processor.py
import redis.asyncio as redis
import json
import asyncio
from typing import Dict, Any, List
from datetime import datetime

# Assuming your project structure allows these imports
# Adjust paths as necessary if your structure is different.
# For example, if 'app' is the root for these modules:
# from app.api.monitoring_endpoints import analyze_flows_for_threats # This might cause circular dependency
# It's better to have a dedicated security analysis service.
# For now, we'll define a placeholder for the analysis trigger.

# Placeholder for database interaction functions (to be implemented in a db service module)
async def store_flow_summary_in_db(flow_summary_data: Dict[str, Any], db_session: Any):
    """Placeholder: Stores parts of the flow summary (like bandwidth, top talkers, protocol dist) into historical tables."""
    # This function will need to:
    # 1. Connect to the database (or use a passed session).
    # 2. Parse flow_summary_data.
    # 3. Create BandwidthHistory, TopTalkersHistory, ProtocolDistributionHistory records.
    # 4. Add them to the session and commit.
    print(f"Placeholder: Storing flow summary in DB at {flow_summary_data.get('timestamp')}")
    # Example:
    # from app.models import BandwidthHistory, TopTalkersHistory, ProtocolDistributionHistory
    # from app.database import SessionLocal
    # async with SessionLocal() as session:
    #     # ... create and add records ...
    #     await session.commit()
    pass

async def trigger_security_analysis_service(analysis_data: Dict[str, Any], db_session: Any):
    """Placeholder: Triggers the security analysis pipeline."""
    # This function will:
    # 1. Instantiate/get security detectors (PortScan, DDoS, MLManager).
    # 2. Call their respective analysis methods with analysis_data.
    # 3. Collect alerts.
    # 4. Store alerts in the database.
    print(f"Placeholder: Triggering security analysis for data timestamp {analysis_data.get('timestamp')}")
    # Example:
    # from app.security.port_scan_detector import PortScanDetector
    # from app.security.ddos_detector import DDoSDetector
    # from app.security.ml_integration_manager import ml_manager # Assuming a global/singleton manager
    # from app.services.alert_service import store_alerts_in_db
    #
    # port_scan_alerts = PortScanDetector().analyze_flows(analysis_data.get("flows", []))
    # ddos_alerts = DDoSDetector().analyze_traffic_and_bandwidth(analysis_data.get("flows", []), analysis_data.get("bandwidth_stats", {}))
    # ml_alerts = await ml_manager.analyze_flow_with_ml(analysis_data) # if analyzing summary, or iterate flows
    # combined_alerts = format_and_combine(port_scan_alerts, ddos_alerts, ml_alerts)
    # await store_alerts_in_db(combined_alerts, db_session)
    pass


class FlowProcessor:
    def __init__(self, redis_url: str = "redis://127.0.0.1:6379"):
        # Ensure redis.asyncio is installed: pip install redis[hiredis]
        self.redis_client = redis.from_url(redis_url)
        self.is_processing = False
        self.processing_task: Optional[asyncio.Task] = None

    async def _subscribe_and_process(self):
        pubsub = self.redis_client.pubsub()
        # Channel name from Rust FlowAggregator's send_to_backend
        await pubsub.subscribe("network_flows") 
        print("FlowProcessor: Subscribed to 'network_flows' Redis channel.")
        
        try:
            async for message in pubsub.listen():
                if message['type'] == 'message':
                    try:
                        # Data from Rust is serialized JSON string
                        flow_summary_data = json.loads(message['data']) 
                        print(f"FlowProcessor: Received flow summary at {flow_summary_data.get('timestamp')}")
                        await self.process_single_flow_summary(flow_summary_data)
                    except json.JSONDecodeError as e:
                        print(f"FlowProcessor Error: Could not decode JSON from message: {e}")
                    except Exception as e:
                        print(f"FlowProcessor Error: Unexpected error processing message: {e}")
        except redis.ConnectionError as e:
            print(f"FlowProcessor Error: Redis connection lost: {e}. Attempting to reconnect...")
            await asyncio.sleep(5) # Wait before trying to resubscribe
            # Recursive call or a loop in start_processing might be needed for robust reconnection
            if self.is_processing: # Only if still supposed to be running
                 await self._subscribe_and_process() # Simplistic retry
        except Exception as e:
            print(f"FlowProcessor Error: Critical error in subscription loop: {e}")
            self.is_processing = False # Stop processing on unhandled critical errors
        finally:
            print("FlowProcessor: Unsubscribed from 'network_flows'.")
            await pubsub.unsubscribe("network_flows")


    async def process_single_flow_summary(self, flow_summary_data: Dict[str, Any]):
        """
        Process an individual flow summary received from Redis.
        This includes storing historical data and triggering security analysis.
        """
        # In a real application, you'd use a dependency injection system or pass a DB session factory
        db_session_placeholder = None # Replace with actual DB session management

        # 1. Store historical monitoring data from the summary
        # This needs to map fields from FlowSummary (Rust) to DB models (Python)
        # e.g., bandwidth_history, top_talkers_history, protocol_distribution_history
        await store_flow_summary_in_db(flow_summary_data, db_session_placeholder)

        # 2. Prepare data for security analysis
        # The `FlowSummary` itself might be enough, or you might extract specific parts.
        # The plan mentioned `extract_flows_for_analysis` - if individual flows are embedded in summary.
        # For now, assume `flow_summary_data` contains what's needed or can be adapted.
        # The DDoS detector expects `flows` list and `bandwidth_stats` dict.
        # PortScan expects `flows` list. ML manager expects a flow dict.
        # This implies the Rust `FlowSummary` should ideally contain a list of individual flow details
        # if per-flow ML/PortScan analysis is desired at this stage.
        # If not, these detectors might need to operate on aggregated data or this part needs rethink.
        
        # For now, let's assume `flow_summary_data` is passed and detectors/services adapt.
        # A more refined `analysis_data` structure might be:
        analysis_data_for_security = {
            "timestamp": flow_summary_data.get("timestamp"),
            "flows": flow_summary_data.get("detailed_flows", []), # Assuming detailed_flows might be part of summary
            "bandwidth_stats": flow_summary_data.get("bandwidth_usage", {}),
            "aggregated_metrics": flow_summary_data # Pass the whole summary for context
        }
        
        # 3. Trigger security analysis (asynchronously)
        # This should not block the processing of further Redis messages.
        asyncio.create_task(trigger_security_analysis_service(analysis_data_for_security, db_session_placeholder))

        # 4. (Optional) Broadcast to WebSockets if needed for live raw summary view
        # This is separate from security alerts which would be broadcast by the alert service.
        # await self.broadcast_to_websockets("flow_summary_update", flow_summary_data)
        print(f"FlowProcessor: Finished processing summary for {flow_summary_data.get('timestamp')}")

    async def broadcast_to_websockets(self, event_type: str, data: Dict[str, Any]):
        """Placeholder: Broadcast data to WebSocket clients via another Redis channel."""
        try:
            await self.redis_client.publish("websocket_updates", json.dumps({
                "type": event_type,
                "data": data,
                "timestamp": datetime.utcnow().isoformat()
            }))
        except Exception as e:
            print(f"FlowProcessor Error: Failed to broadcast to WebSockets: {e}")

    async def start_processing(self):
        """Starts the Redis subscription and message processing loop."""
        if not self.is_processing:
            self.is_processing = True
            print("FlowProcessor: Starting Redis subscription...")
            self.processing_task = asyncio.create_task(self._subscribe_and_process())
            try:
                await self.processing_task # Keep it running
            except asyncio.CancelledError:
                print("FlowProcessor: Processing task was cancelled.")
            except Exception as e:
                print(f"FlowProcessor: Processing task ended with error: {e}")
            finally:
                self.is_processing = False
        else:
            print("FlowProcessor: Already processing.")

    async def stop_processing(self):
        """Stops the Redis subscription and message processing loop."""
        if self.is_processing and self.processing_task:
            self.is_processing = False # Signal loop to stop trying to reconnect if it fails
            self.processing_task.cancel()
            print("FlowProcessor: Stop request sent. Waiting for processing task to finish...")
            try:
                await self.processing_task
            except asyncio.CancelledError:
                print("FlowProcessor: Processing task successfully cancelled.")
            except Exception as e:
                print(f"FlowProcessor: Error during stop: {e}")
            finally:
                self.processing_task = None
                print("FlowProcessor: Stopped.")
        else:
            print("FlowProcessor: Not currently processing or task already gone.")

# Example of how to run this processor (e.g., in your FastAPI startup or a separate script)
async def main():
    processor = FlowProcessor()
    try:
        await processor.start_processing()
        # Keep it running, e.g. by waiting for a shutdown signal
        # For this example, let it run for a bit or until Ctrl+C
        # In a real app, this would be managed by the application lifecycle
        while processor.is_processing:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("FlowProcessor Main: Keyboard interrupt received.")
    finally:
        print("FlowProcessor Main: Shutting down...")
        await processor.stop_processing()
        # Ensure Redis client connections are closed if necessary, though redis-py handles this.
        await processor.redis_client.close() # Explicitly close client
        print("FlowProcessor Main: Shutdown complete.")


if __name__ == "__main__":
    # This allows running the processor standalone for testing
    # You'd need to have a Redis server running.
    # And your Rust engine publishing to "network_flows" channel.
    print("Starting Flow Processor standalone for testing...")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Flow Processor standalone interrupted by user.")
    print("Flow Processor standalone finished.")