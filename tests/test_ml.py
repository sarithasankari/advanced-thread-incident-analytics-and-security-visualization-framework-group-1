"""
Machine Learning and MLOps Unit Tests
Tests predictions playbooks, SHAP explainability, forecasting ARIMA outputs, and PSI drift indices.
"""

import os
import sys
import pytest
import pandas as pd
import numpy as np

# Path configuration
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import settings
from src.prediction import IncidentPredictor
from src.explainability import ThreatExplainer
from src.forecasting import generate_forecasts
from mlops.drift_detector import DriftDetector

@pytest.fixture(scope="module")
def predictor_instance():
    """Initializes the active ML champion predictor."""
    return IncidentPredictor(model_path=settings.MODEL_PATH)

def test_inference_playbook(predictor_instance):
    """Ensures prediction output formats, confidence thresholds, and playbooks are generated."""
    mock_incident = {
        "Attack_Type": "SQL Injection",
        "Protocol": "TCP",
        "Port": 80,
        "Device": "WAF",
        "Country": "US",
        "Failed_Login_Count": 0,
        "Hour": 14,
        "Weekend_Flag": 0,
        "Attack_Frequency": 2,
        "Suspicious_IP_Score": 1.5,
        "Session_Duration": 15.0,
        "User_Role": "Standard Employee",
        "Auth_Method": "Password"
    }
    result = predictor_instance.predict_incident(mock_incident)
    assert "predicted_risk_level" in result
    assert "confidence_pct" in result
    assert "recommendation" in result
    assert result["predicted_risk_level"] in ["Low Risk", "Medium Risk", "High Risk"]
    assert isinstance(result["confidence_pct"], float)

def test_shap_explanations(predictor_instance):
    """Ensures SHAP waterfall attributions and natural-text reasons are compiled."""
    explainer = ThreatExplainer(pipeline=predictor_instance.pipeline)
    mock_incident = {
        "Attack_Type": "Brute Force",
        "Protocol": "TCP",
        "Port": 22,
        "Device": "IDS/IPS",
        "Country": "RU",
        "Failed_Login_Count": 10,
        "Hour": 2,
        "Weekend_Flag": 1,
        "Attack_Frequency": 12,
        "Suspicious_IP_Score": 8.0,
        "Session_Duration": 45.0,
        "User_Role": "Standard Employee",
        "Auth_Method": "Password"
    }
    df_incident = pd.DataFrame([mock_incident])
    # Explain class index 2 (High Risk)
    explanation = explainer.explain_instance(df_incident, 2)
    
    assert "explanations" in explanation
    assert len(explanation["explanations"]) > 0
    # The output explanations list must be standard strings
    assert isinstance(explanation["explanations"][0], str)

def test_time_series_forecasting():
    """Validates that daily forecasting outputs bounded predictions with positive counts."""
    forecast_df, aggregates = generate_forecasts(steps=7)
    
    assert len(forecast_df) == 7
    assert "Forecasted_Count" in forecast_df.columns
    assert "Lower_Bound" in forecast_df.columns
    assert "Upper_Bound" in forecast_df.columns
    # Predictions shouldn't yield negative counts
    assert (forecast_df["Forecasted_Count"] >= 0).all()
    assert "weekly" in aggregates
    assert "monthly" in aggregates

def test_drift_detector_psi():
    """Asserts that PSI calculations correctly capture stable and drifted datasets."""
    detector = DriftDetector(threshold=0.1)
    
    # 1. Stable case (same distribution)
    expected = pd.Series(np.random.normal(0, 1, 1000))
    actual_stable = pd.Series(np.random.normal(0, 1, 1000))
    psi_stable = detector.calculate_psi(expected, actual_stable)
    # Stable PSI should be very small (<0.1)
    assert psi_stable < 0.1
    
    # 2. Drifted case (shifted distribution)
    actual_drifted = pd.Series(np.random.normal(1.5, 1.2, 1000))
    psi_drifted = detector.calculate_psi(expected, actual_drifted)
    # Drifted PSI should be high (>=0.25)
    assert psi_drifted >= 0.25
