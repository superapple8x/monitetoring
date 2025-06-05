# src/security/ml_integration_manager.py
from typing import Dict, List, Optional, Any
import asyncio # For potential async operations if models support it

# Assuming ml_model_adapter is in the same directory
from .ml_model_adapter import MLModelAdapter, SeniorThesisModelAdapter, MLPrediction # Ensure correct import path

class MLIntegrationManager:
    def __init__(self):
        self.models: Dict[str, MLModelAdapter] = {}
        self.active_model_ids: List[str] = [] # Store IDs of active models
        self.model_configs: Dict[str, Dict[str, Any]] = {} # Store loaded configs per model_id

    def register_model(self, model_adapter: MLModelAdapter, config: Optional[Dict[str, Any]] = None):
        """Register a new ML model adapter."""
        if not model_adapter or not hasattr(model_adapter, 'model_id'):
            print("Error: Invalid model adapter provided for registration.")
            return
            
        model_id = model_adapter.model_id
        self.models[model_id] = model_adapter
        self.model_configs[model_id] = config if config is not None else {}
        print(f"Registered ML model: {model_id}")

    def activate_model(self, model_id: str):
        """Activate a model for use in detection."""
        if model_id in self.models and model_id not in self.active_model_ids:
            self.active_model_ids.append(model_id)
            print(f"Activated ML model: {model_id}")
        elif model_id not in self.models:
            print(f"Warning: Model {model_id} not registered. Cannot activate.")
        else:
            print(f"Info: Model {model_id} is already active.")

    def deactivate_model(self, model_id: str):
        """Deactivate a model."""
        if model_id in self.active_model_ids:
            self.active_model_ids.remove(model_id)
            print(f"Deactivated ML model: {model_id}")
        else:
            print(f"Info: Model {model_id} was not active or not registered.")

    async def analyze_flow_with_ml(self, network_flow_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a single network flow with all active ML models.
        Returns a list of alert-formatted dictionaries.
        """
        alerts = []
        
        for model_id in self.active_model_ids:
            model_adapter = self.models.get(model_id)
            if not model_adapter:
                continue

            try:
                processed_features = model_adapter.preprocess_features(network_flow_data)
                if processed_features is None:
                    # Preprocessing failed or decided to skip this flow
                    print(f"Skipping flow for model {model_id} due to preprocessing issue.")
                    continue

                # Assuming predict can be async if needed, but current adapter is sync
                # If predict becomes async: prediction = await model_adapter.predict(processed_features)
                prediction_result: MLPrediction = model_adapter.predict(processed_features)
                
                # Create an alert if the prediction indicates an anomaly
                # The threshold for "anomaly" might be model-specific or configured.
                # Using prediction_result.prediction > 0.5 as a generic example.
                # A more robust way is to check prediction_result.threat_type != "normal" or similar.
                anomaly_threshold = self.model_configs.get(model_id, {}).get("anomaly_decision_threshold", 0.5)

                if prediction_result.prediction > anomaly_threshold or \
                   (prediction_result.threat_type and prediction_result.threat_type not in ["normal", "normal_placeholder", "low_confidence_anomaly"]):
                    alert = self._create_ml_alert_from_prediction(
                        model_id, prediction_result, network_flow_data
                    )
                    alerts.append(alert)
                    
            except Exception as e:
                print(f"Error during ML analysis with model {model_id} for flow: {e}")
                # Optionally, create an error alert or log extensively
                continue
        
        return alerts

    def _create_ml_alert_from_prediction(
        self, model_id: str, prediction: MLPrediction, network_flow_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Helper to format an ML prediction into a standardized alert dictionary."""
        severity = self._calculate_severity_from_confidence(prediction.confidence)
        
        # If threat_type is 'normal' or similar, but prediction score was high, adjust severity or type
        if prediction.threat_type and prediction.threat_type.startswith("normal") and prediction.prediction > 0.5:
            effective_threat_type = "suspicious_ml_activity"
            if prediction.confidence > 0.7: severity = "medium"
        else:
            effective_threat_type = prediction.threat_type or "general_ml_anomaly"

        return {
            'alert_type': 'ml_detection', # Standardized type for ML alerts
            'model_id': model_id,
            'model_name': prediction.model_name or model_id, # Use specific name from prediction if available
            'severity': severity,
            'source_ip': str(network_flow_data.get('src_ip', 'N/A')),
            'target_ip': str(network_flow_data.get('dst_ip', 'N/A')),
            'target_port': network_flow_data.get('dst_port'),
            'protocol': network_flow_data.get('protocol'),
            'timestamp': network_flow_data.get('timestamp', datetime.utcnow().isoformat()),
            'description': f"ML model '{prediction.model_name or model_id}' detected: {effective_threat_type}",
            'confidence_score': round(prediction.confidence, 3),
            'anomaly_score': round(prediction.anomaly_score, 3), # Raw score from model
            'details': {
                'prediction_value': round(prediction.prediction, 3), # Model's class prediction or probability
                'feature_importance': prediction.feature_importance,
                'model_config_used': self.model_configs.get(model_id, {}),
                'flow_duration_sec': network_flow_data.get('duration'), # Assuming duration is already seconds or a convertible type
                'flow_total_bytes': network_flow_data.get('bytes_sent',0) + network_flow_data.get('bytes_received',0),
            }
        }

    def _calculate_severity_from_confidence(self, confidence: float) -> str:
        """Calculate alert severity based on ML model's confidence score."""
        if confidence > 0.9:
            return 'high'
        elif confidence > 0.75:
            return 'medium'
        elif confidence > 0.5:
            return 'low'
        else:
            return 'info' # Or 'low' if info is not a used severity level

    def get_models_info(self) -> Dict[str, Any]:
        """Get information about registered and active models."""
        return {
            'registered_models': list(self.models.keys()),
            'active_models': self.active_model_ids,
            'model_configurations': self.model_configs,
            'model_details': {
                mid: {
                    "adapter_type": type(adapter).__name__,
                    "features_expected": adapter.get_feature_names()[:5] + ["..."] if len(adapter.get_feature_names()) > 5 else adapter.get_feature_names() # Show sample
                } for mid, adapter in self.models.items()
            }
        }

# Setup function to initialize and register models
def setup_ml_integration_manager(
    senior_model_path: Optional[str] = 'models/senior_thesis_model.pkl', # Path from project root
    senior_model_config_path: Optional[str] = 'models/senior_thesis_config.json'
) -> MLIntegrationManager:
    """
    Initializes the MLIntegrationManager and registers available models.
    Paths should be relative to the project root or absolute.
    """
    manager = MLIntegrationManager()

    # Attempt to register the Senior Thesis Model
    try:
        # Assuming the model files are in a 'models' directory at the root of python_api
        # Adjust paths if they are elsewhere.
        # For example, if python_api is the root for these paths:
        # senior_model_path_abs = os.path.join(os.path.dirname(__file__), '..', senior_model_path)
        # senior_config_path_abs = os.path.join(os.path.dirname(__file__), '..', senior_model_config_path)
        
        # For now, assume paths are correct as passed or defaults work for placeholder
        senior_model_adapter = SeniorThesisModelAdapter(model_id="senior_thesis_v1")
        senior_model_adapter.load_model(
            model_path=senior_model_path, 
            config_path=senior_model_config_path
        )
        
        # Example config to pass during registration
        senior_model_reg_config = {
            'description': "Senior's thesis model for general network anomaly detection.",
            'version': "1.0-placeholder",
            'anomaly_decision_threshold': 0.6, # Example: if prediction > 0.6, consider for alert
            'expected_input_source': "Processed NetworkFlow data"
        }
        manager.register_model(senior_model_adapter, config=senior_model_reg_config)
        
        # Activate it by default if it's not just a failing placeholder
        if not senior_model_adapter.is_placeholder:
            manager.activate_model("senior_thesis_v1")
        else:
            print("Senior thesis model is a placeholder; not activating by default.")

    except Exception as e:
        print(f"Critical error setting up SeniorThesisModelAdapter: {e}")

    # Example: Register another type of model if available
    # general_anomaly_adapter = GeneralAnomalyModelAdapter(model_id="iso_forest_std")
    # general_anomaly_adapter.load_model("models/iso_forest_model.pkl") # Example path
    # manager.register_model(general_anomaly_adapter, {"description": "Isolation Forest for general anomalies"})
    # manager.activate_model("iso_forest_std")

    return manager

# Example of how the manager might be used (e.g., in an API endpoint or a processing loop)
async def example_usage_ml_manager():
    ml_manager = setup_ml_integration_manager()
    print("\nML Manager Info:", json.dumps(ml_manager.get_models_info(), indent=2, default=str))

    # Simulate a network flow
    sample_flow = {
        'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'dst_port': 53, 'protocol': 17,
        'duration': timedelta(seconds=0.5), 'bytes_sent': 78, 'bytes_received': 120,
        'packets_sent': 1, 'packets_received': 1, 'avg_packet_size': 99.0,
        'packets_per_second': 2.0, 'bytes_per_second': 396.0,
        'timestamp': datetime.utcnow().isoformat(), 'connection_state': 'unknown'
    }
    
    # If senior_thesis_v1 was not activated due to placeholder, activate it for test
    if "senior_thesis_v1" in ml_manager.models and "senior_thesis_v1" not in ml_manager.active_model_ids:
        ml_manager.activate_model("senior_thesis_v1")


    alerts = await ml_manager.analyze_flow_with_ml(sample_flow)
    if alerts:
        print(f"\nGenerated {len(alerts)} ML alerts for sample flow:")
        for alert_item in alerts:
            print(json.dumps(alert_item, indent=2, default=str))
    else:
        print("\nNo ML alerts generated for the sample flow.")

if __name__ == '__main__':
    asyncio.run(example_usage_ml_manager())