"""
FastAPI Backend Application
Exposes REST endpoints for incident uploads, ML prediction, local SHAP explanation,
time-series forecasting, compliance reports, and JWT authentication with RBAC.
"""

import os
import sys
import json
import numpy as np
from datetime import timedelta
from typing import Dict, List, Any, Optional

# Path configuration for direct execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

# Authentication & Models
from api.auth import (
    hash_password, verify_password, create_access_token, 
    get_current_user, RoleChecker
)
from api.models import (
    UserLoginSchema, UserCreateSchema, UserResponseSchema, TokenSchema,
    IncidentCreateSchema, PredictionRequestSchema, PredictionResponseSchema,
    BatchPredictionResponseSchema, HealthResponseSchema
)

# Core src modules
from src.config import settings
from src.database_manager import (
    get_db_api, db_create_user, db_get_user_by_username, db_add_incident,
    db_add_prediction_log, db_add_audit_log, Incident, PredictionLog
)
from src.prediction import IncidentPredictor
from src.explainability import ThreatExplainer
from src.forecasting import generate_forecasts
from src.alerting_system import trigger_high_risk_alert
from src.utils.logger import get_api_logger

api_logger = get_api_logger()

# Initialize FastAPI App
app = FastAPI(
    title="Advanced Threat Incident Analytics and Security Visualization Framework REST API",
    description="Enterprise-grade REST API backend with JWT authentication and Role-Based Access Control.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Globals for lazy-loaded ML components
predictor: Optional[IncidentPredictor] = None
explainer: Optional[ThreatExplainer] = None

def get_predictor() -> IncidentPredictor:
    """Helper to retrieve/load the ML IncidentPredictor instance."""
    global predictor
    if predictor is None:
        try:
            predictor = IncidentPredictor(model_path=settings.MODEL_PATH)
        except Exception as e:
            api_logger.error(f"Failed to load ML model in API: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Machine learning model is not available. Please train models first."
            )
    return predictor

def get_explainer() -> ThreatExplainer:
    """Helper to retrieve/load the ThreatExplainer instance."""
    global explainer
    if explainer is None:
        try:
            pred_instance = get_predictor()
            explainer = ThreatExplainer(pipeline=pred_instance.pipeline)
        except Exception as e:
            api_logger.error(f"Failed to load SHAP explainer in API: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Interpretability explainer is not available."
            )
    return explainer

# ==========================================
# 1. AUTHENTICATION & USER MANAGEMENT
# ==========================================

@app.post("/api/auth/register", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
def register_user(
    payload: UserCreateSchema, 
    db: Session = Depends(get_db_api),
    admin_user: UserResponseSchema = Depends(RoleChecker(allowed_roles=["Admin"]))
):
    """Registers a new user account. Restricted to Admin role only."""
    existing_user = db_get_user_by_username(db, payload.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered."
        )
    hashed = hash_password(payload.password)
    user = db_create_user(db, payload.username, hashed, payload.role)
    
    # Audit log entry
    db_add_audit_log(db, admin_user.username, f"Registered new user '{payload.username}' with role '{payload.role}'")
    
    return user.to_dict()

@app.post("/api/auth/token", response_model=TokenSchema)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db_api)):
    """OAuth2 compatible token login route. Issues a JWT access token on success."""
    user = db_get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        api_logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, 
        expires_delta=access_token_expires
    )
    
    # Audit log entry
    db_add_audit_log(db, user.username, "User logged in successfully")
    api_logger.info(f"User '{user.username}' authenticated successfully (Role: {user.role})")
    
    return {"access_token": access_token, "token_type": "bearer"}

# ==========================================
# 2. INCIDENT INGESTION GATEWAY
# ==========================================

@app.post("/api/incidents/upload", status_code=status.HTTP_201_CREATED)
def upload_incidents(
    incidents: List[IncidentCreateSchema],
    db: Session = Depends(get_db_api),
    current_user: Any = Depends(RoleChecker(allowed_roles=["Admin", "Security Analyst"]))
):
    """Uploads and validates a batch of threat incidents. Inserts them into the database."""
    api_logger.info(f"User '{current_user.username}' uploading {len(incidents)} incidents...")
    
    try:
        inserted_count = 0
        for item in incidents:
            db_add_incident(db, item.model_dump())
            inserted_count += 1
            
        db_add_audit_log(
            db=db,
            username=current_user.username,
            action=f"Ingested and committed {inserted_count} incident records via REST API."
        )
        return {"message": "Success", "records_ingested": inserted_count}
    except Exception as e:
        api_logger.error(f"Failed to ingest incidents: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save incidents: {str(e)}"
        )

# ==========================================
# 3. REAL-TIME THREAT PREDICTOR & ALERTS
# ==========================================

@app.post("/api/predict", response_model=PredictionResponseSchema)
def predict_threat_level(
    payload: PredictionRequestSchema,
    db: Session = Depends(get_db_api),
    current_user: Any = Depends(RoleChecker(allowed_roles=["Admin", "Security Analyst"])),
    ml_predictor: IncidentPredictor = Depends(get_predictor)
):
    """Classifies a single incident threat level using the active ML champion. Generates alerts if risk is High."""
    raw_data = payload.model_dump()
    
    try:
        result = ml_predictor.predict_incident(raw_data)
        
        # Inject mock IP attributes for auditing log purposes
        src_ip = f"192.168.1.{np.random.randint(10, 250)}"
        dst_ip = f"10.100.1.{np.random.randint(1, 10)}"
        raw_data["Source_IP"] = src_ip
        raw_data["Destination_IP"] = dst_ip
        
        # Save prediction audit trace
        db_add_prediction_log(
            db=db,
            source_ip=src_ip,
            dest_ip=dst_ip,
            attack_type=payload.Attack_Type,
            risk_level=result["predicted_risk_level"],
            confidence=result["confidence_pct"],
            rec=result["recommendation"],
            features=raw_data
        )
        
        alert_details = None
        # 14. Trigger Alerting System if classification is High Risk
        if result["predicted_risk_level"] == "High Risk":
            alert_details = trigger_high_risk_alert(raw_data, result, db=db)
            
        db_add_audit_log(
            db=db,
            username=current_user.username,
            action=f"Executed ML prediction on {payload.Attack_Type} from {src_ip}. Result: {result['predicted_risk_level']}"
        )
        
        return {
            "predicted_risk_level": result["predicted_risk_level"],
            "confidence_pct": result["confidence_pct"],
            "recommendation": result["recommendation"],
            "all_probabilities": result["all_probabilities"],
            "alert_details": alert_details
        }
    except Exception as e:
        api_logger.error(f"Inference execution failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )

# ==========================================
# 4. EXPLAINABLE AI (XAI) WITH SHAP
# ==========================================

@app.post("/api/predict/explain")
def predict_and_explain(
    payload: PredictionRequestSchema,
    current_user: Any = Depends(RoleChecker(allowed_roles=["Admin", "Security Analyst"])),
    ml_predictor: IncidentPredictor = Depends(get_predictor),
    ml_explainer: ThreatExplainer = Depends(get_explainer)
):
    """Classifies risk and generates local SHAP feature impact attributes with natural language reasons."""
    raw_data = payload.model_dump()
    
    try:
        # 1. Run prediction
        pred_res = ml_predictor.predict_incident(raw_data)
        
        # Determine index of predicted class
        risk_labels = {0: "Low Risk", 1: "Medium Risk", 2: "High Risk"}
        inverse_labels = {v: k for k, v in risk_labels.items()}
        pred_idx = inverse_labels.get(pred_res["predicted_risk_level"], 0)
        
        # 2. Convert raw incident data dict to DataFrame for shap preprocessor mapping
        df_incident = pd.DataFrame([raw_data])
        
        # 3. Calculate SHAP values
        shap_res = ml_explainer.explain_instance(df_incident, pred_idx)
        
        return {
            "prediction": pred_res,
            "shap_explanation": shap_res
        }
    except Exception as e:
        api_logger.error(f"Failed to generate SHAP explanations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Explainability error: {str(e)}"
        )

# ==========================================
# 5. SECURITY FORECASTING & INTEL
# ==========================================

@app.get("/api/forecast")
def get_attack_forecasts(
    steps: int = 30,
    current_user: Any = Depends(RoleChecker(allowed_roles=["Admin", "Security Analyst", "Viewer"]))
):
    """Retrieves 30-day time-series projections of alert volumes. Accessible to all authenticated users."""
    try:
        f_df, aggregates = generate_forecasts(steps=steps)
        # Parse dates to strings for JSON serialization
        f_df['Date'] = f_df['Date'].dt.strftime("%Y-%m-%d")
        return {
            "forecast_days": f_df.to_dict(orient='records'),
            "aggregates": aggregates
        }
    except Exception as e:
        api_logger.error(f"Time-series forecast endpoint failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forecasting error: {str(e)}"
        )

# ==========================================
# 6. SYSTEM HEALTH & DIAGNOSTICS
# ==========================================

@app.get("/api/health", response_model=HealthResponseSchema)
def get_health_status(db: Session = Depends(get_db_api)):
    """Public diagnostic endpoint. Checks database connection and champion model load status."""
    db_connected = False
    try:
        # Run simple SELECT 1 to verify database responsiveness
        db.execute(text("SELECT 1"))
        db_connected = True
    except Exception as e:
        api_logger.error(f"Health check failed database connectivity: {str(e)}")

    model_loaded = False
    model_name = None
    model_f1 = None
    
    # Check if champion model metrics exist
    metrics_path = settings.METRICS_PATH
    model_path = settings.MODEL_PATH
    if os.path.exists(metrics_path) and os.path.exists(model_path):
        try:
            with open(metrics_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                model_name = meta.get("best_model_name")
                # Pull F1 score
                model_f1 = meta.get("metrics", {}).get(model_name, {}).get("f1_score")
            model_loaded = True
        except Exception as e:
            api_logger.error(f"Health check failed reading metrics: {str(e)}")
    else:
        api_logger.warning(f"Health check: metrics_path {metrics_path} exists={os.path.exists(metrics_path)}, model_path {model_path} exists={os.path.exists(model_path)}")

    status_str = "Healthy" if (db_connected and model_loaded) else "Degraded"
    
    return {
        "status": status_str,
        "database_connected": db_connected,
        "model_loaded": model_loaded,
        "champion_model_name": model_name,
        "champion_model_f1": model_f1
    }
