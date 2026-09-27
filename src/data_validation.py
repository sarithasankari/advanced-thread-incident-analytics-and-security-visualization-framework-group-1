"""
Data Validation Module
Declares Pydantic schemas for data integrity checks and compiles detailed
Data Quality reports (identifying duplicates, nulls, outliers, invalid IPs, etc.).
"""

import ipaddress
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from pydantic import BaseModel, Field, field_validator

class SecurityIncidentSchema(BaseModel):
    """Pydantic schema defining a valid security incident payload."""
    Timestamp: str
    Source_IP: str
    Destination_IP: str
    Attack_Type: str
    Protocol: str
    Port: int = Field(..., ge=0, le=65535)
    Severity: str
    Status: str
    Country: str
    Device: str
    Action_Taken: str
    Failed_Login_Count: int = Field(0, ge=0)
    Session_Duration: float = Field(0.0, ge=0.0)

    @field_validator("Timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Ensures the timestamp fits ISO format."""
        try:
            pd.to_datetime(v)
            return v
        except Exception:
            raise ValueError("Timestamp must be parseable as a datetime.")

    @field_validator("Source_IP", "Destination_IP")
    @classmethod
    def validate_ips(cls, v: str) -> str:
        """Validates IP format using python's built-in ipaddress module."""
        try:
            ipaddress.ip_address(v.strip())
            return v.strip()
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

    @field_validator("Attack_Type")
    @classmethod
    def validate_attack(cls, v: str) -> str:
        """Validates attack classification types."""
        valid_attacks = {"DDoS", "SQL Injection", "Brute Force", "Phishing", "Malware", "Port Scanning"}
        if v not in valid_attacks:
            raise ValueError(f"Attack Type must be one of: {valid_attacks}")
        return v

    @field_validator("Protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """Validates network protocol tags."""
        valid_protocols = {"TCP", "UDP", "ICMP"}
        if v.upper() not in valid_protocols:
            raise ValueError(f"Protocol must be one of: {valid_protocols}")
        return v.upper()

    @field_validator("Severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validates reported severity categories."""
        valid_severities = {"Low", "Medium", "High", "Critical"}
        if v not in valid_severities:
            raise ValueError(f"Severity must be one of: {valid_severities}")
        return v

    @field_validator("Status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validates event lifecycle status indicators."""
        valid_status = {"Detected", "Blocked", "Mitigated", "Ignored"}
        if v not in valid_status:
            raise ValueError(f"Status must be one of: {valid_status}")
        return v

    @field_validator("Action_Taken")
    @classmethod
    def validate_action(cls, v: str) -> str:
        """Validates mitigation playbooks actions taken."""
        valid_actions = {"Blocked", "Logged", "Alerted", "Isolated"}
        if v not in valid_actions:
            raise ValueError(f"Action Taken must be one of: {valid_actions}")
        return v


class DataValidator:
    """Ingests dataframes, checks rows using Pydantic, and compiles data quality telemetry reports."""

    @staticmethod
    def validate_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
        """
        Validates a dataframe row-by-row against SecurityIncidentSchema.
        Returns a tuple of (clean_dataframe, validation_error_log).
        """
        valid_rows = []
        errors = []

        for idx, row in df.iterrows():
            row_dict = row.to_dict()
            # Clean string conversions for comparison
            row_dict["Port"] = int(row_dict["Port"]) if str(row_dict.get("Port")).isdigit() else -1
            row_dict["Failed_Login_Count"] = int(row_dict["Failed_Login_Count"]) if str(row_dict.get("Failed_Login_Count")).isdigit() else -1
            row_dict["Session_Duration"] = float(row_dict["Session_Duration"]) if str(row_dict.get("Session_Duration")).replace('.', '', 1).isdigit() else -1.0
            
            try:
                # Validate using Pydantic
                validated_model = SecurityIncidentSchema(**row_dict)
                valid_rows.append(validated_model.model_dump())
            except Exception as e:
                errors.append({
                    "row_index": int(idx),
                    "original_data": row_dict,
                    "validation_errors": str(e)
                })

        clean_df = pd.DataFrame(valid_rows) if valid_rows else pd.DataFrame(columns=df.columns)
        return clean_df, errors

    @staticmethod
    def generate_quality_report(df: pd.DataFrame) -> Dict[str, Any]:
        """Compiles standard diagnostic telemetry of missing values, duplicates, outliers, and invalid data."""
        report: Dict[str, Any] = {}
        total_records = len(df)
        report["total_records"] = total_records
        
        if total_records == 0:
            report["status"] = "Empty Dataset"
            return report

        # 1. Missing Values
        missing_counts = df.isnull().sum().to_dict()
        report["missing_values"] = {k: int(v) for k, v in missing_counts.items() if v > 0}

        # 2. Duplicate entries
        duplicate_count = int(df.duplicated().sum())
        report["duplicates"] = {
            "count": duplicate_count,
            "percentage": round((duplicate_count / total_records) * 100, 2)
        }

        # 3. Invalid IPs
        invalid_src_ip_count = 0
        invalid_dst_ip_count = 0
        for ip in df["Source_IP"].dropna().unique():
            try:
                ipaddress.ip_address(str(ip).strip())
            except ValueError:
                invalid_src_ip_count += (df["Source_IP"] == ip).sum()
        for ip in df["Destination_IP"].dropna().unique():
            try:
                ipaddress.ip_address(str(ip).strip())
            except ValueError:
                invalid_dst_ip_count += (df["Destination_IP"] == ip).sum()

        report["invalid_ips"] = {
            "source_ip_errors": int(invalid_src_ip_count),
            "destination_ip_errors": int(invalid_dst_ip_count)
        }

        # 4. Outliers detection using IQR (for Failed_Login_Count and Session_Duration)
        outliers: Dict[str, Any] = {}
        for num_col in ["Failed_Login_Count", "Session_Duration"]:
            if num_col in df.columns:
                q1 = df[num_col].quantile(0.25)
                q3 = df[num_col].quantile(0.75)
                iqr = q3 - q1
                lower_bound = q1 - 1.5 * iqr
                upper_bound = q3 + 1.5 * iqr
                outliers_count = int(((df[num_col] < lower_bound) | (df[num_col] > upper_bound)).sum())
                outliers[num_col] = {
                    "count": outliers_count,
                    "upper_bound": float(upper_bound),
                    "lower_bound": float(lower_bound)
                }
        report["outliers"] = outliers

        # Overall Status Rating
        total_errors = (
            sum(missing_counts.values()) + 
            duplicate_count + 
            invalid_src_ip_count + 
            invalid_dst_ip_count
        )
        error_pct = (total_errors / total_records) * 100
        
        if error_pct == 0:
            report["integrity_rating"] = "Excellent (0% error rate)"
        elif error_pct < 2:
            report["integrity_rating"] = "Good (<2% error rate)"
        elif error_pct < 8:
            report["integrity_rating"] = "Warning (<8% error rate)"
        else:
            report["integrity_rating"] = "Critical (High error density)"

        return report
