"""
API REST Route Integration Tests
Tests JWT token login flows, authentication blocks, and Role-Based Access Control (RBAC).
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Path configuration
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from api.main import app

client = TestClient(app)

def test_health_check_endpoint():
    """Asserts that the diagnostic health check returns success and database status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "database_connected" in data
    assert data["database_connected"] is True

def test_unauthenticated_endpoint_block():
    """Asserts that protected API routes return HTTP 401 when accessed without JWT headers."""
    response = client.post("/api/predict", json={})
    assert response.status_code == 401

def test_admin_auth_and_rbac_flow():
    """
    Tests JWT credential validation, role token generation, 
    and checks that Viewer role access is forbidden for uploads.
    """
    # 1. Login as Admin
    login_response = client.post(
        "/api/auth/token",
        data={"username": "admin", "password": "admin123"}
    )
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    admin_token = token_data["access_token"]
    
    # 2. Login as Viewer
    viewer_login = client.post(
        "/api/auth/token",
        data={"username": "viewer", "password": "viewer123"}
    )
    assert viewer_login.status_code == 200
    viewer_token = viewer_login.json()["access_token"]

    # 3. Test prediction using Admin token
    headers = {"Authorization": f"Bearer {admin_token}"}
    prediction_payload = {
        "Attack_Type": "SQL Injection",
        "Protocol": "TCP",
        "Port": 3306,
        "Device": "WAF",
        "Country": "US",
        "Failed_Login_Count": 1,
        "Hour": 12,
        "Weekend_Flag": 0,
        "Attack_Frequency": 3,
        "Suspicious_IP_Score": 1.2,
        "Session_Duration": 15.0,
        "User_Role": "Standard Employee",
        "Auth_Method": "Password"
    }
    pred_response = client.post("/api/predict", json=prediction_payload, headers=headers)
    assert pred_response.status_code == 200
    pred_data = pred_response.json()
    assert "predicted_risk_level" in pred_data
    assert pred_data["predicted_risk_level"] in ["Low Risk", "Medium Risk", "High Risk"]

    # 4. Test RBAC: Ingest upload block for Viewer
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    upload_payload = [{
        "Timestamp": "2026-08-04 12:00:00",
        "Source_IP": "10.0.0.9",
        "Destination_IP": "10.100.1.5",
        "Attack_Type": "DDoS",
        "Protocol": "TCP",
        "Port": 80,
        "Severity": "High",
        "Status": "Detected",
        "Country": "US",
        "Device": "Firewall",
        "Action_Taken": "Logged",
        "Failed_Login_Count": 0,
        "Session_Duration": 1.5
    }]
    # Upload is restricted to Admin & Security Analyst, so Viewer should get 403 Forbidden
    upload_response = client.post("/api/incidents/upload", json=upload_payload, headers=viewer_headers)
    assert upload_response.status_code == 403
