# src/redis/flow_processor.py
import redis.asyncio as redis
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

# Import the new intelligent monitoring system
from ..monitoring.intelligent_network_monitor import IntelligentNetworkMonitor, NetworkHealthReport

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

async def analyze_network_health_with_intelligence(flow_summary_data: Dict[str, Any], 
                                                  intelligent_monitor: IntelligentNetworkMonitor) -> NetworkHealthReport:
    """
    Analyze network health using the intelligent monitoring system.
    Combines security and performance analysis for superior insights.
    """
    try:
        # The flow_summary_data from Rust now includes security_awareness
        health_report = await intelligent_monitor.analyze_network_health(flow_summary_data)
        
        logging.info(f"Network health analysis complete: Score {health_report.overall_health_score:.2f}, "
                    f"Threats: {len(health_report.security_status.active_threats)}")
        
        # Log important insights
        if health_report.overall_health_score < 0.5:
            logging.warning(f"Poor network health detected: {health_report.correlation_insights}")
        
        if health_report.security_status.active_threats:
            logging.warning(f"Active security threats: {health_report.security_status.active_threats}")
        
        return health_report
        
    except Exception as e:
        logging.error(f"Error in intelligent network health analysis: {e}")
        # Return a basic health report with error status
        from ..monitoring.intelligent_network_monitor import NetworkPerformanceAnalysis, SecurityThreatAnalysis
        return NetworkHealthReport(
            timestamp=datetime.utcnow(),
            performance=NetworkPerformanceAnalysis(
                average_latency_ms=0.0,
                jitter_ms=0.0,
                packet_loss_percentage=0.0,
                throughput_mbps=0.0,
                connection_success_rate=1.0,
                performance_score=0.5
            ),
            security_status=SecurityThreatAnalysis(
                threat_level='unknown',
                active_threats=[],
                confidence_score=0.0,
                affected_assets=[]
            ),
            overall_health_score=0.5,
            correlation_insights=["Error analyzing network health"],
            recommended_actions=["Check monitoring system status"]
        )


class FlowProcessor:
    def __init__(self, redis_url: str = "redis://127.0.0.1:6379"):
        # Ensure redis.asyncio is installed: pip install redis[hiredis]
        self.redis_client = redis.from_url(redis_url)
        self.is_processing = False
        self.processing_task: Optional[asyncio.Task] = None
        
        # Initialize the intelligent network monitor
        self.intelligent_monitor = IntelligentNetworkMonitor()
        self.latest_health_report: Optional[NetworkHealthReport] = None

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
        Process an individual flow summary received from Redis using intelligent monitoring.
        This includes storing historical data and performing intelligent network health analysis.
        """
        try:
            # 1. Store historical monitoring data from the summary
            db_session_placeholder = None  # Replace with actual DB session management
            await store_flow_summary_in_db(flow_summary_data, db_session_placeholder)

            # 2. Perform intelligent network health analysis
            # This combines security and performance analysis using the enhanced data from Rust
            health_report = await analyze_network_health_with_intelligence(
                flow_summary_data, self.intelligent_monitor
            )
            
            # Store the latest health report for API access
            self.latest_health_report = health_report
            
            # 3. Broadcast intelligent insights to WebSocket clients
            await self.broadcast_intelligent_insights(health_report)
            
            # 4. Log important findings
            if health_report.security_status.active_threats:
                logging.warning(f"Security threats detected: {health_report.security_status.active_threats}")
                
            if health_report.overall_health_score < 0.7:
                logging.info(f"Network health attention needed: {health_report.recommended_actions}")
            
            logging.debug(f"FlowProcessor: Intelligent analysis complete for {flow_summary_data.get('timestamp')}")
            
        except Exception as e:
            logging.error(f"FlowProcessor: Error processing flow summary: {e}")
    
    async def broadcast_intelligent_insights(self, health_report: NetworkHealthReport):
        """Broadcast intelligent network insights to WebSocket clients"""
        try:
            insights_payload = {
                "type": "INTELLIGENT_NETWORK_INSIGHTS",
                "payload": {
                    "timestamp": health_report.timestamp.isoformat(),
                    "overall_health_score": health_report.overall_health_score,
                    "security_status": {
                        "threat_level": health_report.security_status.threat_level,
                        "active_threats": health_report.security_status.active_threats,
                        "confidence_score": health_report.security_status.confidence_score,
                        "affected_assets": health_report.security_status.affected_assets
                    },
                    "performance_metrics": {
                        "average_latency_ms": health_report.performance.average_latency_ms,
                        "throughput_mbps": health_report.performance.throughput_mbps,
                        "performance_score": health_report.performance.performance_score
                    },
                    "correlation_insights": health_report.correlation_insights,
                    "recommended_actions": health_report.recommended_actions,
                    "performance_impact_of_attacks": health_report.performance_impact_of_attacks
                }
            }
            
            await self.redis_client.publish("websocket_updates", json.dumps(insights_payload))
            logging.debug("Broadcast intelligent insights to WebSocket clients")
            
        except Exception as e:
            logging.error(f"FlowProcessor: Failed to broadcast intelligent insights: {e}")
    
    def get_latest_health_report(self) -> Optional[NetworkHealthReport]:
        """Get the latest network health report for API access"""
        return self.latest_health_report

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