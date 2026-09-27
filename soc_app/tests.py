"""
Django REST Framework Integration Tests
Verifies health checks, JWT token exchange, prediction, forecasting, and RBAC permission blocks.
"""

import json
from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

class SOCAPITests(TestCase):
    """Verifies Django REST Framework gateways, SimpleJWT checks, and RBAC role blocks."""

    def setUp(self) -> None:
        self.client = APIClient()
        
        # 1. Create default users and profiles
        self.admin_user = User.objects.create_user(username="admin_test", password="adminpassword123")
        self.admin_user.profile.role = "Admin"
        self.admin_user.profile.save()
        
        self.analyst_user = User.objects.create_user(username="analyst_test", password="analystpassword123")
        self.analyst_user.profile.role = "Security Analyst"
        self.analyst_user.profile.save()
        
        self.viewer_user = User.objects.create_user(username="viewer_test", password="viewerpassword123")
        self.viewer_user.profile.role = "Viewer"
        self.viewer_user.profile.save()

    def test_health_diagnostic_endpoint(self):
        """Asserts that the diagnostic vitals check endpoint returns success."""
        response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["database_connected"], True)
        self.assertIn("status", data)

    def test_unauthenticated_endpoint_prevention(self):
        """Asserts that protected endpoints block anonymous requests with HTTP 401."""
        response = self.client.post("/api/predict/", {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_jwt_token_auth_and_rbac_flow(self):
        """
        Validates SimpleJWT token logins, role authentication, 
        and verifies that Viewer access is blocked on incident uploads.
        """
        # 1. Exchange credentials for JWT access token
        login_res = self.client.post(
            "/api/auth/token/",
            {"username": "admin_test", "password": "adminpassword123"}
        )
        print("LOGIN RESPONSE STATUS:", login_res.status_code)
        print("LOGIN RESPONSE DATA:", login_res.data)
        self.assertEqual(login_res.status_code, status.HTTP_200_OK)
        token_data = login_res.data
        admin_token = token_data["access_token"]
        
        # 2. Login as Viewer
        viewer_login = self.client.post(
            "/api/auth/token/",
            {"username": "viewer_test", "password": "viewerpassword123"}
        )
        self.assertEqual(viewer_login.status_code, status.HTTP_200_OK)
        viewer_token = viewer_login.data["access_token"]

        # 3. Test predictions endpoint with Admin token
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
        prediction_payload = {
            "Attack_Type": "SQL Injection",
            "Protocol": "TCP",
            "Port": 80,
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
        pred_res = self.client.post("/api/predict/", prediction_payload, format="json")
        self.assertEqual(pred_res.status_code, status.HTTP_200_OK)
        self.assertIn("predicted_risk_level", pred_res.data)
        
        # 4. Test explain predictions endpoint
        explain_res = self.client.post("/api/predict/explain/", prediction_payload, format="json")
        self.assertEqual(explain_res.status_code, status.HTTP_200_OK)
        self.assertIn("shap_explanation", explain_res.data)

        # 5. Test RBAC: Uploading incidents must fail for the Viewer role
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {viewer_token}")
        upload_payload = [{
            "timestamp": "2026-08-04 12:00:00",
            "source_ip": "10.0.0.9",
            "destination_ip": "10.100.1.5",
            "attack_type": "DDoS",
            "protocol": "TCP",
            "port": 80,
            "severity": "High",
            "status": "Detected",
            "country": "US",
            "device": "Firewall",
            "action_taken": "Logged",
            "failed_login_count": 0,
            "session_duration": 1.5
        }]
        upload_res = self.client.post("/api/incidents/upload/", upload_payload, format="json")
        # Viewers do not have upload permissions -> HTTP 403 Forbidden
        self.assertEqual(upload_res.status_code, status.HTTP_403_FORBIDDEN)
