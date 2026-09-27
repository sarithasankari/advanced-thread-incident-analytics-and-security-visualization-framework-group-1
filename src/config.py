"""
Configuration Module
Loads, validates, and manages environmental configurations for the application settings.
"""

import os
from typing import Dict, Any

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

class Settings:
    """Manages application configurations loaded from config/settings.env or environment variables."""
    
    def __init__(self, env_file: str = None) -> None:
        if env_file is None:
            self.env_file = os.path.join(BASE_DIR, "config", "settings.env")
        else:
            self.env_file = env_file
        self.config: Dict[str, str] = {}
        self._load_env_file()
        
    def _load_env_file(self) -> None:
        """Parses the configuration file and populates the configuration dict."""
        if os.path.exists(self.env_file):
            with open(self.env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        self.config[key.strip()] = val.strip()
                        
    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration parameter by key. Checks environment variables first."""
        # Check system environment variables first for production overrides
        if key in os.environ:
            return os.environ[key]
        return self.config.get(key, default)

    @property
    def LOG_DIR(self) -> str:
        """Directory path for log outputs."""
        return str(self.get("LOG_DIR", "logs"))

    @property
    def DATABASE_URL(self) -> str:
        """Database connection string."""
        return str(self.get("DATABASE_URL", "sqlite:///database/db_sqlite.db"))

    @property
    def JWT_SECRET_KEY(self) -> str:
        """Secret key used to encrypt and sign JWT tokens."""
        return str(self.get("JWT_SECRET_KEY", "fallbacksecret_superkey_for_jwt_auth_12345!"))

    @property
    def JWT_ALGORITHM(self) -> str:
        """Encryption algorithm used for JWT token signing."""
        return str(self.get("JWT_ALGORITHM", "HS256"))

    @property
    def ACCESS_TOKEN_EXPIRE_MINUTES(self) -> int:
        """Expirations duration for access tokens in minutes."""
        return int(self.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

    @property
    def MODEL_PATH(self) -> str:
        """File path to the champion machine learning pipeline model."""
        path = str(self.get("MODEL_PATH", "models/best_model.joblib"))
        return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)

    @property
    def METRICS_PATH(self) -> str:
        """File path to the champion model metrics summary JSON."""
        path = str(self.get("METRICS_PATH", "models/model_metrics.json"))
        return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)

    @property
    def ALERT_EMAIL_SENDER(self) -> str:
        """Sender email address for alerts."""
        return str(self.get("ALERT_EMAIL_SENDER", "soc-alerts@enterprise.com"))

    @property
    def ALERT_EMAIL_RECEIVER(self) -> str:
        """Receiver email address for alerts."""
        return str(self.get("ALERT_EMAIL_RECEIVER", "security-response@enterprise.com"))

    @property
    def SMTP_HOST(self) -> str:
        """SMTP server hostname."""
        return str(self.get("SMTP_HOST", "smtp.enterprise.com"))

    @property
    def SMTP_PORT(self) -> int:
        """SMTP server port."""
        return int(self.get("SMTP_PORT", 587))

    @property
    def RETRAIN_DRIFT_THRESHOLD(self) -> float:
        """Threshold drift score (PSI) that triggers automated retraining."""
        return float(self.get("RETRAIN_DRIFT_THRESHOLD", 0.15))

    @property
    def MODEL_REGISTRY_DIR(self) -> str:
        """Directory path for model version control storage."""
        path = str(self.get("MODEL_REGISTRY_DIR", "models/registry"))
        return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)

# Instantiate settings globally
settings = Settings()
