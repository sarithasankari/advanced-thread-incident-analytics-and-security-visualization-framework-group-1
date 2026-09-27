"""
Django REST Framework (DRF) API Views
Implements endpoints for auth, incident logs upload, prediction, forecasting, SHAP XAI, and diagnostics.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List

from django.contrib.auth.models import User
from rest_framework import status, views, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from soc_app.models import Profile, Incident, PredictionLog, AuditLog
from soc_app.serializers import (
    UserSerializer, UserCreateSerializer, IncidentSerializer, PredictionRequestSerializer
)

# Core ML and forecasting imports
from src.config import settings
from src.prediction import IncidentPredictor
from src.explainability import ThreatExplainer
from src.forecasting import generate_forecasts
from src.alerting_system import trigger_high_risk_alert
from src.utils.logger import get_api_logger

api_logger = get_api_logger()

# ==========================================
# 1. JWT CUSTOMIZER & Role-Based Permissions
# ==========================================

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Customizes SimpleJWT to encode user roles directly in JWT payloads."""
    @classmethod
    def get_token(cls, user) -> Any:
        token = super().get_token(user)
        # Add custom token payload claims
        token['username'] = user.username
        token['role'] = user.profile.role if hasattr(user, 'profile') else 'Viewer'
        return token

    def validate(self, attrs) -> Dict[str, Any]:
        data = super().validate(attrs)
        # Remap token keys for frontend client compatibility
        data['access_token'] = data.pop('access')
        data['token_type'] = 'bearer'
        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class IsAdmin(permissions.BasePermission):
    """Checks if the authenticated user has Admin role permissions."""
    def has_permission(self, request, view) -> bool:
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'profile') and 
            request.user.profile.role == 'Admin'
        )

class IsSecurityAnalystOrAdmin(permissions.BasePermission):
    """Checks if user role is Admin or Security Analyst."""
    def has_permission(self, request, view) -> bool:
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'profile') and 
            request.user.profile.role in ['Admin', 'Security Analyst']
        )

class IsViewerOrAbove(permissions.BasePermission):
    """Checks if user role is Viewer, Analyst, or Admin."""
    def has_permission(self, request, view) -> bool:
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'profile') and 
            request.user.profile.role in ['Admin', 'Security Analyst', 'Viewer']
        )

# ==========================================
# 2. ENDPOINT VIEWS
# ==========================================

class UserRegisterView(views.APIView):
    """Allows Admin to register new users with specific roles."""
    permission_classes = [IsAdmin]

    def post(self, request) -> Response:
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Log audit trace
            AuditLog.objects.create(
                username=request.user.username,
                action=f"Registered user '{user.username}' (Role: {user.profile.role})",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class IncidentUploadView(views.APIView):
    """Ingests security incident logs into the target database."""
    permission_classes = [IsSecurityAnalystOrAdmin]

    def post(self, request) -> Response:
        # Check if request data is list
        data_list = request.data if isinstance(request.data, list) else [request.data]
        
        saved_incidents = []
        for raw_log in data_list:
            serializer = IncidentSerializer(data=raw_log)
            if serializer.is_valid():
                saved_incidents.append(serializer)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        # Commit to database
        for ser in saved_incidents:
            ser.save()
            
        AuditLog.objects.create(
            username=request.user.username,
            action=f"Uploaded and committed {len(saved_incidents)} threat incidents via DRF Gateway.",
            ip_address=request.META.get('REMOTE_ADDR')
        )
        return Response({"message": "Success", "records_ingested": len(saved_incidents)}, status=status.HTTP_201_CREATED)


class PredictionView(views.APIView):
    """Executes champion model risk classification on a single telemetry input."""
    permission_classes = [IsSecurityAnalystOrAdmin]

    def post(self, request) -> Response:
        serializer = PredictionRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        raw_data = serializer.validated_data
        
        try:
            predictor = IncidentPredictor(model_path=settings.MODEL_PATH)
            result = predictor.predict_incident(raw_data)
            
            # Inject mock IPs
            src_ip = f"192.168.1.{np.random.randint(10, 250)}"
            dst_ip = f"10.100.1.{np.random.randint(1, 10)}"
            
            # Save prediction audit log entry
            PredictionLog.objects.create(
                source_ip=src_ip,
                dest_ip=dst_ip,
                attack_type=raw_data["Attack_Type"],
                risk_level=result["predicted_risk_level"],
                confidence=result["confidence_pct"],
                recommendation=result["recommendation"],
                features_json=json.dumps(raw_data)
            )
            
            alert_details = None
            if result["predicted_risk_level"] == "High Risk":
                # Convert raw incident dictionary to include IPs for the alerting playbook
                telemetry = raw_data.copy()
                telemetry["Source_IP"] = src_ip
                telemetry["Destination_IP"] = dst_ip
                # Call trigger alert
                alert_details = trigger_high_risk_alert(telemetry, result, db=None)
                
                # Write an audit log warning
                AuditLog.objects.create(
                    username="SYSTEM_ML_CLASSIFIER",
                    action=f"CRITICAL WARNING: High Risk {raw_data['Attack_Type']} from {src_ip} detected. Incident ticket created: {alert_details.get('ticket_id')}",
                    ip_address=src_ip
                )
                
            AuditLog.objects.create(
                username=request.user.username,
                action=f"Calculated prediction risk for {raw_data['Attack_Type']} from {src_ip}. Result: {result['predicted_risk_level']}",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            response_payload = {
                "predicted_risk_level": result["predicted_risk_level"],
                "confidence_pct": result["confidence_pct"],
                "recommendation": result["recommendation"],
                "all_probabilities": result["all_probabilities"],
                "alert_details": alert_details
            }
            return Response(response_payload, status=status.HTTP_200_OK)
            
        except Exception as e:
            api_logger.error(f"Inference execution failed inside DRF View: {str(e)}", exc_info=True)
            return Response({"detail": f"Inference engine failure: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PredictionExplainView(views.APIView):
    """Calculates risk levels and yields local SHAP explanations."""
    permission_classes = [IsSecurityAnalystOrAdmin]

    def post(self, request) -> Response:
        serializer = PredictionRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        raw_data = serializer.validated_data
        
        try:
            predictor = IncidentPredictor(model_path=settings.MODEL_PATH)
            pred_res = predictor.predict_incident(raw_data)
            
            # Translate risk string back to class index
            risk_labels = {0: "Low Risk", 1: "Medium Risk", 2: "High Risk"}
            inverse_labels = {v: k for k, v in risk_labels.items()}
            pred_idx = inverse_labels.get(pred_res["predicted_risk_level"], 0)
            
            explainer = ThreatExplainer(pipeline=predictor.pipeline)
            df_incident = pd.DataFrame([raw_data])
            shap_res = explainer.explain_instance(df_incident, pred_idx)
            
            return Response({
                "prediction": pred_res,
                "shap_explanation": shap_res
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            api_logger.error(f"SHAP explanation calculation failed: {str(e)}", exc_info=True)
            return Response({"detail": f"SHAP calculation failure: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AttackForecastView(views.APIView):
    """Provides time-series alert frequency projections."""
    permission_classes = [IsViewerOrAbove]

    def get(self, request) -> Response:
        steps = int(request.query_params.get("steps", 30))
        try:
            forecast_df, aggregates = generate_forecasts(steps=steps)
            forecast_df['Date'] = forecast_df['Date'].dt.strftime("%Y-%m-%d")
            return Response({
                "forecast_days": forecast_df.to_dict(orient='records'),
                "aggregates": aggregates
            }, status=status.HTTP_200_OK)
        except Exception as e:
            api_logger.error(f"Arima forecasting request failed: {str(e)}", exc_info=True)
            return Response({"detail": f"Forecasting error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class HealthView(views.APIView):
    """Public diagnostic endpoint. Checks database response and model registry states."""
    permission_classes = [permissions.AllowAny]

    def get(self, request) -> Response:
        db_connected = False
        try:
            # Direct Django raw query to confirm database responsiveness
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            db_connected = True
        except Exception as e:
            api_logger.error(f"Health check failed database connectivity: {str(e)}")

        model_loaded = False
        model_name = None
        model_f1 = None
        
        metrics_path = settings.METRICS_PATH
        if os.path.exists(metrics_path) and os.path.exists(settings.MODEL_PATH):
            try:
                with open(metrics_path, "r") as f:
                    meta = json.load(f)
                    model_name = meta.get("best_model_name")
                    model_f1 = meta.get("metrics", {}).get(model_name, {}).get("f1_score")
                model_loaded = True
            except Exception:
                pass

        status_str = "Healthy" if (db_connected and model_loaded) else "Degraded"
        
        return Response({
            "status": status_str,
            "database_connected": db_connected,
            "model_loaded": model_loaded,
            "champion_model_name": model_name,
            "champion_model_f1": model_f1
        }, status=status.HTTP_200_OK)
