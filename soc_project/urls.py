"""
soc_project URL Configuration
Maps Django URL paths to REST API view handlers.
"""

from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from soc_app.views import (
    CustomTokenObtainPairView, UserRegisterView, IncidentUploadView,
    PredictionView, PredictionExplainView, AttackForecastView, HealthView
)

urlpatterns = [
    # Admin Interface
    path('admin/', admin.site.urls),
    
    # JWT Authentication Endpoints
    path('api/auth/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/register/', UserRegisterView.as_view(), name='user_register'),
    
    # Security Telemetry Ingest Gateway
    path('api/incidents/upload/', IncidentUploadView.as_view(), name='incident_upload'),
    
    # ML Classifiers Inference & Interpretability Portals
    path('api/predict/', PredictionView.as_view(), name='incident_predict'),
    path('api/predict/explain/', PredictionExplainView.as_view(), name='incident_predict_explain'),
    
    # Capacity Planning time-series forecasts
    path('api/forecast/', AttackForecastView.as_view(), name='attack_forecast'),
    
    # Public Vitals Diagnostics
    path('api/health/', HealthView.as_view(), name='platform_health'),
]
