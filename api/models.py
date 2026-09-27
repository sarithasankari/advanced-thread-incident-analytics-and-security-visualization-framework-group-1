"""
API Models Module
Defines Pydantic request and response schemas for FastAPI endpoints.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class UserLoginSchema(BaseModel):
    """Credentials payload for JWT token exchange."""
    username: str = Field(..., examples=["analyst_user"])
    password: str = Field(..., examples=["secure_pass123"])

class UserCreateSchema(BaseModel):
    """Payload for registering new users (Admin privileges required)."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = Field("Viewer", pattern="^(Admin|Security Analyst|Viewer)$")

class UserResponseSchema(BaseModel):
    """Public user profile response."""
    id: int
    username: str
    role: str
    created_at: str

class TokenSchema(BaseModel):
    """JWT response structure."""
    access_token: str
    token_type: str = "bearer"

class IncidentCreateSchema(BaseModel):
    """Schema for reporting a new threat incident."""
    Timestamp: str = Field(..., description="ISO 8601/Standard datetime string")
    Source_IP: str = Field(..., description="Attacking IPv4 address")
    Destination_IP: str = Field(..., description="Target IPv4 address")
    Attack_Type: str = Field(..., description="Attack category")
    Protocol: str = Field(..., description="TCP/UDP/ICMP")
    Port: int = Field(..., ge=0, le=65535)
    Severity: str = Field(..., description="Low/Medium/High/Critical")
    Status: str = Field(..., description="Detected/Blocked/Mitigated/Ignored")
    Country: str = Field(..., description="ISO Country code")
    Device: str = Field(..., description="Reporting security appliance")
    Action_Taken: str = Field(..., description="Action taken")
    Failed_Login_Count: int = Field(0, ge=0)
    Session_Duration: float = Field(0.0, ge=0.0)
    User_Agent: Optional[str] = None
    Latitude: Optional[float] = None
    Longitude: Optional[float] = None
    User_Role: Optional[str] = None
    Auth_Method: Optional[str] = None
    Geo_Region: Optional[str] = None

class PredictionRequestSchema(BaseModel):
    """Input telemetry fields required for real-time ML threat classification."""
    Attack_Type: str
    Protocol: str
    Port: int
    Device: str
    Country: str
    Failed_Login_Count: int
    Hour: int
    Weekend_Flag: int
    Attack_Frequency: int
    Suspicious_IP_Score: float
    Session_Duration: float = 0.0
    User_Role: str = "Standard Employee"
    Auth_Method: str = "Password"

class PredictionResponseSchema(BaseModel):
    """Response structure returned by the threat classification model."""
    predicted_risk_level: str
    confidence_pct: float
    recommendation: str
    all_probabilities: Dict[str, float]
    alert_details: Optional[Dict[str, Any]] = None

class BatchPredictionResponseSchema(BaseModel):
    """Response model for bulk uploads predictions."""
    total_processed: int
    high_risk_alerts: int
    predictions: List[Dict[str, Any]]

class HealthResponseSchema(BaseModel):
    """Self-check diagnostics model health response."""
    status: str
    database_connected: bool
    model_loaded: bool
    champion_model_name: Optional[str] = None
    champion_model_f1: Optional[float] = None
