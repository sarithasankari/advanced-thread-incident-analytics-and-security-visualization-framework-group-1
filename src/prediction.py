"""
Prediction Module
Provides inference capabilities to classify a single security incident's threat level,
determine the confidence percentage, and generate recommended response actions.
"""

import os
import joblib
import pandas as pd

class IncidentPredictor:
    """Loads the trained model pipeline and runs predictions on new threat incidents."""
    
    def __init__(self, model_path="models/best_model.joblib"):
        self.model_path = model_path
        self.pipeline = None
        self.risk_labels = {0: "Low Risk", 1: "Medium Risk", 2: "High Risk"}
        self.load_model()
        
    def load_model(self):
        """Loads the serialized joblib pipeline."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found at: {self.model_path}. Train the model first.")
        self.pipeline = joblib.load(self.model_path)
        print(f"Prediction model pipeline loaded successfully from: {self.model_path}")

    def predict_incident(self, incident_data):
        """
        Predicts threat level for a single incident dict.
        Expects incident_data to contain:
        - Attack_Type (str)
        - Protocol (str)
        - Port (int)
        - Device (str)
        - Country (str)
        - Failed_Login_Count (int)
        - Hour (int)
        - Weekend_Flag (int: 0/1)
        - Attack_Frequency (int)
        - Suspicious_IP_Score (float)
        """
        if self.pipeline is None:
            self.load_model()
            
        # Convert dictionary to DataFrame
        df = pd.DataFrame([incident_data])
        
        # Verify columns are present
        required_cols = [
            'Attack_Type', 'Protocol', 'Port', 'Device', 'Country', 
            'Failed_Login_Count', 'Hour', 'Weekend_Flag', 'Attack_Frequency', 'Suspicious_IP_Score'
        ]
        for col in required_cols:
            if col not in df.columns:
                raise ValueError(f"Missing required feature: '{col}'")
                
        # Inject default values for columns present in training but missing in single telemetry inputs
        feature_names = None
        if hasattr(self.pipeline, 'feature_names_in_'):
            feature_names = self.pipeline.feature_names_in_
        elif hasattr(self.pipeline.named_steps.get('preprocessor'), 'feature_names_in_'):
            feature_names = self.pipeline.named_steps['preprocessor'].feature_names_in_
            
        if feature_names is not None:
            for col in feature_names:
                if col not in df.columns:
                    df[col] = 0.0
                
        # Perform inference
        prediction_id = self.pipeline.predict(df)[0]
        probabilities = self.pipeline.predict_proba(df)[0]
        
        # Map predicted class and confidence
        predicted_class = self.risk_labels.get(int(prediction_id), "Unknown")
        confidence = float(probabilities[int(prediction_id)]) * 100.0
        
        # Get recommendation
        recommendation = self._get_recommendation(predicted_class, incident_data)
        
        return {
            "predicted_risk_level": predicted_class,
            "confidence_pct": round(confidence, 2),
            "recommendation": recommendation,
            "all_probabilities": {self.risk_labels[i]: round(float(p) * 100, 2) for i, p in enumerate(probabilities)}
        }
        
    def _get_recommendation(self, risk_level, data):
        """Generates dynamic, actionable response playbook actions based on risk level and attack type."""
        device = data.get('Device', 'Security appliance')
        dest = data.get('Destination_IP', 'target network segment')
        src = data.get('Source_IP', 'attacker host')
        attack = data.get('Attack_Type', 'Incident')
        
        if risk_level == "High Risk":
            return (
                f"**CRITICAL PLAYBOOK CRITERIA MET**\n"
                f"- **Isolate**: Request immediate endpoint quarantine for destination {dest}.\n"
                f"- **Block**: Add firewall rule to block traffic from Source IP {src}.\n"
                f"- **Escalate**: Trigger Alert-1 incident response pager for the Security Operations Team (SOC).\n"
                f"- **Details**: {attack} detected on monitoring device '{device}'."
            )
        elif risk_level == "Medium Risk":
            return (
                f"**ALERT GENERATED - ACTIVE MONITORING REQUIRED**\n"
                f"- **Observe**: Perform a packet capture (PCAP) scan on the conversation between {src} and {dest}.\n"
                f"- **Mitigate**: Verify access control list (ACL) rules for port {data.get('Port', 'any')} on {device}.\n"
                f"- **Audit**: Analyze login attempts; detected {data.get('Failed_Login_Count', 0)} failed logins from this IP.\n"
                f"- **Remediation**: Queue target system for standard patch assessment."
            )
        else:
            return (
                f"**INFORMATIONAL LOG ONLY**\n"
                f"- **Assess**: No immediate response needed. Log entry saved.\n"
                f"- **Baseline**: Record telemetry of {attack} traffic on '{device}'.\n"
                f"- **Verify**: Ensure generic ingress filter policies remain operational."
            )

if __name__ == "__main__":
    # Test class with simple mock input (will only work if models are trained and saved)
    try:
        predictor = IncidentPredictor()
        mock_incident = {
            "Attack_Type": "Brute Force",
            "Protocol": "TCP",
            "Port": 22,
            "Device": "IDS/IPS",
            "Country": "RU",
            "Failed_Login_Count": 8,
            "Hour": 2,
            "Weekend_Flag": 1,
            "Attack_Frequency": 15,
            "Suspicious_IP_Score": 8.5
        }
        result = predictor.predict_incident(mock_incident)
        print("Mock incident prediction result:")
        print(result)
    except Exception as e:
        print(f"Skipping main execution test: {str(e)}")
