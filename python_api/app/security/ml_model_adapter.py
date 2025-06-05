# src/security/ml_model_adapter.py
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import numpy as np
import joblib # For loading scikit-learn models
import json
from dataclasses import dataclass, field
import datetime # For time-based features

@dataclass
class MLPrediction:
    prediction: float # Typically, 0 for normal, 1 for anomaly, or a probability score
    confidence: float # Confidence in the prediction, 0.0 to 1.0
    anomaly_score: float # Raw anomaly score from the model, if applicable
    feature_importance: Dict[str, float] = field(default_factory=dict)
    threat_type: Optional[str] = None # e.g., 'port_scan', 'ddos_syn_flood', 'general_anomaly'
    model_name: Optional[str] = None # Name of the model that made the prediction


class MLModelAdapter(ABC):
    """Abstract base class for ML model adapters"""
    
    def __init__(self, model_id: str):
        self.model_id = model_id

    @abstractmethod
    def load_model(self, model_path: str, config_path: Optional[str] = None):
        """Load the ML model from file and optional configuration."""
        pass
    
    @abstractmethod
    def preprocess_features(self, network_flow_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract and preprocess features from network flow data. Returns a 1D numpy array or None if preprocessing fails."""
        pass
    
    @abstractmethod
    def predict(self, processed_features: np.ndarray) -> MLPrediction:
        """Make prediction on preprocessed features."""
        pass
    
    @abstractmethod
    def get_feature_names(self) -> List[str]:
        """Get list of feature names expected by the model."""
        pass

class SeniorThesisModelAdapter(MLModelAdapter):
    """Adapter for your senior's thesis model (or a placeholder)."""
    
    DEFAULT_FEATURE_NAMES = [
        'duration_sec', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
        'avg_packet_size', 'packets_per_second', 'bytes_per_second', 'total_bytes', 'total_packets',
        'is_tcp', 'is_udp', 'is_icmp', 'dst_port',
        'is_web_port', 'is_system_port', 'is_admin_port',
        'hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekday',
        'conn_state_established', 'conn_state_syn', 'conn_state_fin', 'conn_state_reset', 'conn_state_unknown'
    ]

    def __init__(self, model_id: str = "senior_thesis_model"):
        super().__init__(model_id)
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None # For feature scaling if used
        self.feature_names: List[str] = self.DEFAULT_FEATURE_NAMES[:] # Use a copy
        self.model_config: Dict[str, Any] = {}
        self.is_placeholder: bool = True # Flag to indicate if actual model is loaded

    def load_model(self, model_path: str, config_path: Optional[str] = None):
        """Load the senior's thesis model and associated components."""
        try:
            # Attempt to load the model (e.g., a scikit-learn model)
            model_data = joblib.load(model_path)
            
            if isinstance(model_data, dict):
                self.model = model_data.get('model')
                self.scaler = model_data.get('scaler')
                loaded_feature_names = model_data.get('feature_names')
                if loaded_feature_names and isinstance(loaded_feature_names, list):
                    self.feature_names = loaded_feature_names
            else: # Assuming the loaded object is the model itself
                self.model = model_data
            
            if self.model is not None:
                self.is_placeholder = False
                print(f"Successfully loaded model '{self.model_id}' from {model_path}")
            else:
                print(f"Warning: Model component not found in {model_path} for '{self.model_id}'. Using placeholder.")
                self.is_placeholder = True

        except FileNotFoundError:
            print(f"Warning: Model file {model_path} not found for '{self.model_id}'. Using placeholder.")
            self.is_placeholder = True
        except Exception as e:
            print(f"Error loading model '{self.model_id}' from {model_path}: {e}. Using placeholder.")
            self.is_placeholder = True
            self.model = None # Ensure model is None on error
            self.scaler = None

        if config_path:
            try:
                with open(config_path, 'r') as f:
                    self.model_config = json.load(f)
                print(f"Successfully loaded config for '{self.model_id}' from {config_path}")
                # Potentially override feature_names from config if present
                if "feature_names" in self.model_config and isinstance(self.model_config["feature_names"], list):
                    self.feature_names = self.model_config["feature_names"]
            except Exception as e:
                print(f"Error loading model config from {config_path}: {e}")
    
    def preprocess_features(self, network_flow_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract features according to the senior's model requirements."""
        features = []
        try:
            # Duration (ensure it's in seconds)
            duration_val = network_flow_data.get('duration', 0.0) # Default to 0.0 seconds
            if isinstance(duration_val, timedelta):
                features.append(duration_val.total_seconds())
            elif isinstance(duration_val, dict) and "secs" in duration_val: # from Rust SystemTime
                 features.append(duration_val.get("secs",0) + duration_val.get("nanos",0)/1e9)
            else: # Assuming float or int representing seconds
                features.append(float(duration_val))

            # Traffic volume
            features.extend([
                float(network_flow_data.get('bytes_sent', 0)),
                float(network_flow_data.get('bytes_received', 0)),
                float(network_flow_data.get('packets_sent', 0)),
                float(network_flow_data.get('packets_received', 0)),
            ])
            
            # Derived metrics (already calculated in Rust flow)
            features.extend([
                float(network_flow_data.get('avg_packet_size', 0.0)),
                float(network_flow_data.get('packets_per_second', 0.0)),
                float(network_flow_data.get('bytes_per_second', 0.0)),
            ])
            features.append(float(network_flow_data.get('bytes_sent', 0)) + float(network_flow_data.get('bytes_received', 0))) # total_bytes
            features.append(float(network_flow_data.get('packets_sent', 0)) + float(network_flow_data.get('packets_received', 0))) # total_packets

            # Protocol features (one-hot encode)
            protocol = int(network_flow_data.get('protocol', 0))
            features.extend([
                1.0 if protocol == 6 else 0.0,  # is_tcp
                1.0 if protocol == 17 else 0.0, # is_udp
                1.0 if protocol == 1 else 0.0,  # is_icmp
            ])
            
            dst_port = int(network_flow_data.get('dst_port', 0))
            features.append(float(dst_port))
            features.extend([
                1.0 if dst_port in [80, 443, 8080, 8443] else 0.0, # is_web_port
                1.0 if 0 < dst_port < 1024 else 0.0,  # is_system_port (well-known)
                1.0 if dst_port in [21, 22, 23, 25, 110, 143, 3389] else 0.0, # is_admin_port (example)
            ])
            
            # Time-based features
            ts_str = network_flow_data.get('timestamp', datetime.datetime.utcnow().isoformat())
            timestamp = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if isinstance(ts_str, str) else datetime.datetime.utcnow()

            features.extend([
                float(timestamp.hour),
                float(timestamp.weekday()), # Monday=0, Sunday=6
                1.0 if 9 <= timestamp.hour <= 17 else 0.0,  # is_business_hours (approx)
                1.0 if timestamp.weekday() < 5 else 0.0,  # is_weekday
            ])
            
            # Connection state features (one-hot encode)
            conn_state = str(network_flow_data.get('connection_state', 'Unknown')).lower()
            features.extend([
                1.0 if conn_state == 'established' else 0.0,
                1.0 if conn_state in ['synsent', 'synreceived', 'syn_sent', 'syn_received'] else 0.0,
                1.0 if conn_state in ['finwait', 'fin_wait', 'closed'] else 0.0, # 'closed' might be too late
                1.0 if conn_state == 'reset' else 0.0,
                1.0 if conn_state == 'unknown' else 0.0,
            ])

            if len(features) != len(self.feature_names):
                print(f"Warning: Feature length mismatch for '{self.model_id}'. Expected {len(self.feature_names)}, got {len(features)}. Flow: {network_flow_data}")
                # Pad with zeros or truncate if necessary, or return None
                # For now, let's try to pad/truncate to match self.feature_names length
                if len(features) > len(self.feature_names):
                    features = features[:len(self.feature_names)]
                else:
                    features.extend([0.0] * (len(self.feature_names) - len(features)))

            feature_array = np.array(features, dtype=np.float32).reshape(1, -1)
            
            if self.scaler and not self.is_placeholder:
                feature_array = self.scaler.transform(feature_array)
            
            return feature_array[0] # Return 1D array
        except Exception as e:
            print(f"Error during preprocessing for '{self.model_id}': {e}. Flow data: {network_flow_data}")
            return None

    def predict(self, processed_features: np.ndarray) -> MLPrediction:
        """Make prediction using the senior's model or placeholder logic."""
        feature_imp_dict = dict(zip(self.feature_names, processed_features.tolist()))

        if self.is_placeholder or self.model is None:
            # Placeholder logic: e.g., return 'normal' with low confidence
            return MLPrediction(
                prediction=0.0, confidence=0.1, anomaly_score=0.0,
                feature_importance=feature_imp_dict, threat_type="normal_placeholder", model_name=self.model_id
            )

        try:
            features_for_model = processed_features.reshape(1, -1)
            
            # Actual model prediction
            raw_prediction: Any
            if hasattr(self.model, 'predict_proba'): # Classifier
                proba = self.model.predict_proba(features_for_model)[0]
                # Assuming class 1 is anomaly, class 0 is normal
                prediction_val = float(proba[1]) if len(proba) > 1 else float(proba[0]) 
                confidence_val = float(np.abs(proba[0] - proba[1])) if len(proba) > 1 else float(proba[0])
                anomaly_score_val = prediction_val 
            elif hasattr(self.model, 'decision_function'): # e.g., IsolationForest, OneClassSVM
                score = self.model.decision_function(features_for_model)[0]
                # Typically, negative scores are anomalies for decision_function based outlier detectors
                prediction_val = 1.0 if score < self.model_config.get("decision_threshold", 0.0) else 0.0 
                confidence_val = float(1 / (1 + np.exp(-np.abs(score)))) # Sigmoid of abs score for confidence
                anomaly_score_val = float(score)
            elif hasattr(self.model, 'predict'): # Generic predict
                raw_prediction = self.model.predict(features_for_model)[0]
                # Interpret raw_prediction based on model type (e.g. if it's 0/1 or a score)
                prediction_val = float(raw_prediction > self.model_config.get("prediction_threshold", 0.5)) # Example
                confidence_val = 0.6 # Default confidence if not derivable
                anomaly_score_val = float(raw_prediction)
            else:
                raise NotImplementedError("Model does not have 'predict_proba', 'decision_function', or 'predict'")

            # Feature importance (if available)
            if hasattr(self.model, 'feature_importances_'):
                importances = self.model.feature_importances_
                feature_imp_dict = dict(zip(self.feature_names, importances.tolist()))
            
            threat_type = self._determine_threat_type(prediction_val, processed_features)

            return MLPrediction(
                prediction=prediction_val, confidence=confidence_val, anomaly_score=anomaly_score_val,
                feature_importance=feature_imp_dict, threat_type=threat_type, model_name=self.model_id
            )

        except Exception as e:
            print(f"Error during prediction with '{self.model_id}': {e}")
            return MLPrediction(
                prediction=0.0, confidence=0.0, anomaly_score=0.0, # Indicate error or uncertainty
                feature_importance=feature_imp_dict, threat_type="prediction_error", model_name=self.model_id
            )

    def _determine_threat_type(self, prediction_value: float, features: np.ndarray) -> Optional[str]:
        """Determine a plausible threat type based on prediction and (optionally) features."""
        if prediction_value < self.model_config.get("anomaly_threshold_for_threat_typing", 0.7): # Only type if strongly anomalous
            return "normal" if prediction_value < 0.3 else "low_confidence_anomaly"

        # Example heuristic based on features (indices assume DEFAULT_FEATURE_NAMES order)
        # This is highly dependent on the actual model and features.
        # For a placeholder, this can be very basic.
        # Example: if 'packets_per_second' (idx 6) is very high
        if len(features) > 6 and features[6] > 1000: # packets_per_second
            return "potential_ddos_pps"
        # Example: if 'is_syn' (idx ~21) is true and many ports involved (needs more context than single flow)
        # This kind of cross-flow correlation is better handled by rule-based systems or specialized models.
        
        return "general_ml_anomaly" # Default if specific type not clear

    def get_feature_names(self) -> List[str]:
        """Get list of feature names used by the model."""
        return self.feature_names


# Example of a different adapter (can be in a separate file later)
class GeneralAnomalyModelAdapter(MLModelAdapter):
    def __init__(self, model_id: str = "general_anomaly_detector"):
        super().__init__(model_id)
        self.model = None # Placeholder for a different model type
        self.feature_names = ["feat1", "feat2", "duration_sec", "total_packets"] # Example

    def load_model(self, model_path: str, config_path: Optional[str] = None):
        print(f"Placeholder: Load general anomaly model '{self.model_id}' from {model_path}")
        # self.model = ... load actual model
        self.is_placeholder = True # Assume placeholder for now

    def preprocess_features(self, network_flow_data: Dict[str, Any]) -> Optional[np.ndarray]:
        # Simplified preprocessing for this example
        try:
            duration = float(network_flow_data.get('duration', 0.0))
            if isinstance(duration_val := network_flow_data.get('duration'), timedelta): duration = duration_val.total_seconds()
            
            total_packets = float(network_flow_data.get('packets_sent', 0)) + float(network_flow_data.get('packets_received', 0))
            # Dummy features
            feat1 = duration / (total_packets + 1e-6)
            feat2 = total_packets / (duration + 1e-6)
            return np.array([feat1, feat2, duration, total_packets], dtype=np.float32)
        except:
            return None


    def predict(self, processed_features: np.ndarray) -> MLPrediction:
        # Placeholder prediction
        anomaly_score = float(np.sum(processed_features) % 100) / 100.0 # Dummy score
        prediction = 1.0 if anomaly_score > 0.7 else 0.0
        confidence = 0.5 # Dummy confidence
        return MLPrediction(
            prediction=prediction, confidence=confidence, anomaly_score=anomaly_score,
            feature_importance=dict(zip(self.get_feature_names(), processed_features.tolist())),
            threat_type="general_placeholder_anomaly" if prediction > 0.5 else "normal_placeholder",
            model_name=self.model_id
        )

    def get_feature_names(self) -> List[str]:
        return self.feature_names