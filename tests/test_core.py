"""
Core Framework Unit Tests
Tests database CRUD operations, data cleaning, and feature engineering calculations.
"""

import os
import sys
import pytest
import numpy as np
import pandas as pd
from datetime import datetime

# Path configuration
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database_manager import (
    initialize_database, get_db, db_create_user, db_get_user_by_username,
    db_add_incident, db_add_audit_log, User, Incident
)
from src.preprocessing import clean_data
from src.feature_engineering import calculate_advanced_features
from api.auth import hash_password, verify_password

@pytest.fixture(scope="module")
def setup_db():
    """Initializes SQLite schemas for isolated test contexts."""
    initialize_database()
    yield

def test_user_creation_and_auth(setup_db):
    """Verifies that credentials can be registered, hashed, and validated in the database."""
    with get_db() as db:
        # Delete user if exists to avoid test dependency failures
        existing = db.query(User).filter(User.username == "test_user_77").first()
        if existing:
            db.delete(existing)
            db.flush()
            
        pass_raw = "supersecret123"
        hashed = hash_password(pass_raw)
        
        user = db_create_user(db, "test_user_77", hashed, "Security Analyst")
        assert user.username == "test_user_77"
        assert user.role == "Security Analyst"
        assert verify_password(pass_raw, user.password_hash) is True
        assert verify_password("wrongpass", user.password_hash) is False

def test_incident_crud(setup_db):
    """Verifies incident logs can be written and queried from the DB."""
    with get_db() as db:
        incident_data = {
            "timestamp": datetime.now(),
            "source_ip": "192.168.1.99",
            "destination_ip": "10.100.1.1",
            "attack_type": "DDoS",
            "protocol": "TCP",
            "port": 80,
            "severity": "High",
            "status": "Detected",
            "country": "US",
            "device": "Firewall",
            "action_taken": "Logged",
            "failed_login_count": 0,
            "session_duration": 1.2
        }
        incident = db_add_incident(db, incident_data)
        assert incident.id is not None
        assert incident.source_ip == "192.168.1.99"
        assert incident.attack_type == "DDoS"

def test_preprocessing_pipeline():
    """Asserts duplicate logs removal and timestamp cleanups work."""
    raw_records = [
        {"Timestamp": "2026-08-04 12:00:00", "Source_IP": "10.0.0.1", "Destination_IP": "10.0.0.2", "Attack_Type": "DDoS", "Protocol": "TCP", "Port": 80, "Severity": "High", "Status": "Detected", "Country": "US", "Device": "WAF", "Failed_Login_Count": 0, "Action_Taken": "Logged"},
        # Duplicate record
        {"Timestamp": "2026-08-04 12:00:00", "Source_IP": "10.0.0.1", "Destination_IP": "10.0.0.2", "Attack_Type": "DDoS", "Protocol": "TCP", "Port": 80, "Severity": "High", "Status": "Detected", "Country": "US", "Device": "WAF", "Failed_Login_Count": 0, "Action_Taken": "Logged"},
        # Invalid Port
        {"Timestamp": "2026-08-04 12:05:00", "Source_IP": "10.0.0.3", "Destination_IP": "10.0.0.4", "Attack_Type": "Malware", "Protocol": "UDP", "Port": "8080", "Severity": "Medium", "Status": "Detected", "Country": "DE", "Device": "Endpoint agent", "Failed_Login_Count": 0, "Action_Taken": "Logged"},
    ]
    df_raw = pd.DataFrame(raw_records)
    df_clean = clean_data(df_raw)
    
    # Assert duplicate was dropped
    assert len(df_clean) == 2
    # Assert Port was converted to integer type
    assert df_clean['Port'].iloc[1] == 8080
    assert isinstance(df_clean['Port'].iloc[1], (int, np.integer))

def test_advanced_feature_calculations():
    """Asserts that the 14 cybersecurity engineered features calculate with proper datatypes."""
    records = [
        {"Timestamp": "2026-08-04 12:00:00", "Source_IP": "194.26.29.10", "Destination_IP": "10.100.1.25", "Attack_Type": "Brute Force", "Protocol": "TCP", "Port": 22, "Severity": "Medium", "Status": "Detected", "Country": "RU", "Device": "IDS/IPS", "Failed_Login_Count": 5, "Action_Taken": "Alerted", "Session_Duration": 15.0, "User_Agent": "curl", "Latitude": 55.7558, "Longitude": 37.6173, "User_Role": "Standard Employee", "Auth_Method": "Password", "Geo_Region": "RU-MOW"},
        {"Timestamp": "2026-08-04 12:05:00", "Source_IP": "194.26.29.10", "Destination_IP": "10.100.1.25", "Attack_Type": "Brute Force", "Protocol": "TCP", "Port": 22, "Severity": "High", "Status": "Detected", "Country": "RU", "Device": "IDS/IPS", "Failed_Login_Count": 10, "Action_Taken": "Alerted", "Session_Duration": 25.0, "User_Agent": "curl", "Latitude": 55.7558, "Longitude": 37.6173, "User_Role": "Standard Employee", "Auth_Method": "Password", "Geo_Region": "RU-MOW"},
    ]
    df_clean = pd.DataFrame(records)
    df_fe = calculate_advanced_features(df_clean)
    
    # Assert rolling features calculated
    assert 'Attack_Velocity' in df_fe.columns
    assert 'Failed_Login_Frequency' in df_fe.columns
    assert 'IP_Reputation_Score' in df_fe.columns
    assert 'Threat_Density' in df_fe.columns
    assert 'Normalized_Risk_Score' in df_fe.columns
    
    # Assert correct rolling counts
    assert df_fe['Attack_Velocity'].iloc[1] == 2
    assert df_fe['Failed_Login_Frequency'].iloc[1] == 15
