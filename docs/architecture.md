# System Architecture & Technical Specifications

This document outlines the detailed system design, mathematical formulas, and microservice flows governing the Advanced Threat Incident Analytics framework.

---

## 1. Data Processing and Security Feature Engineering

The platform ingests telemetry logs and calculates **14 advanced cybersecurity features** mapping network packets to behavioral scores:

| Feature Name | Type | Mathematical / Logical Calculation | Security Objective |
| :--- | :--- | :--- | :--- |
| **Hour** | Integer | Hours fraction of timestamp: $[0, 23]$ | Identifies off-hours threat activity |
| **Weekend_Flag** | Binary | $1$ if day is Saturday/Sunday, else $0$ | Identifies weekend telemetry anomalies |
| **Attack_Velocity** | Integer | Rolling count of incidents from the same `Source_IP` in past 1 hour | Detects high-frequency automated scans / scans sweeps |
| **Failed_Login_Frequency** | Integer | Rolling sum of `Failed_Login_Count` from the same `Source_IP` in past 1 hour | Detects active brute-force exploits |
| **IP_Reputation_Score** | Float | Weighted ratio of block/isolate actions vs. total actions for the `Source_IP` | Rates malicious historic profile |
| **Threat_Density** | Float | Rolling count of alerts grouped by `Geo_Region` in past 2 hours | Highlights geo-targeted campaigns / botnets |
| **Normalized_Risk_Score** | Float | Weighted combination of failed logins, reputation, and velocity | Unified threat scale $[0.0, 10.0]$ |
| **Historical_Threat_Count**| Integer | Lifetime count of logged threats for specific source node | Tracks persistent attackers |
| **Country_Risk_Score** | Float | Historical ratio of High/Critical severity events originating from target country | Evaluates geographical risk profiles |
| **Device_Risk_Score** | Float | Historical ratio of blocked actions handled by sensor device | Evaluates sensor activity loads |
| **Login_Time_Anomaly** | Binary | $1$ if failed login occurs between 11 PM and 5 AM, else $0$ | Highlights suspicious off-hour logins |
| **Session_Duration_Anomaly**| Float | Standard deviations deviation from mean session length | Identifies data exfiltration channels |
| **Geographic_Anomaly_Score**| Float | Velocity deviation from average regional incident logs | Highlights impossible travel anomalies |
| **Attack_Burst_Detection** | Binary | $1$ if rolling 10-minute alert volume crosses 3x standard deviation, else $0$ | Identifies active DDoS / flood bursts |

---

## 2. Machine Learning Pipeline & Champion Selection

### Model Comparison Strategy
We train, evaluate, and tune 6 major models sequentially in a stratified 3-fold cross-validation loop:
- **Random Forest**: Baseline ensemble decision trees.
- **XGBoost**: Extreme Gradient Boosting optimized with parallel tree splits.
- **LightGBM**: Fast histogram-based tree booster.
- **CatBoost**: Categorical boosting handling categorical encodings.
- **Extra Trees**: Extremely randomized decision forests.
- **Gradient Boosting**: Sequential tree estimator (scikit-learn baseline).

The model scoring the highest **weighted F1-Score** on the validation set is selected as the champion and saved to `models/best_model.joblib`. Under current evaluations, **Gradient Boosting Classifier** won champion status with an F1 score of **90.63%** and Accuracy of **90.80%**.

---

## 3. MLOps Model Registry & Drift Detection

### Population Stability Index (PSI)
Data drift is evaluated using the PSI index which compares a baseline reference distribution ($E$) with a target distribution ($A$):

$$PSI = \sum_{i=1}^{B} \left( (A_i - E_i) \times \ln\left(\frac{A_i}{E_i}\right) \right)$$

Where:
- $B$ is the total number of bins (quantile bins for numeric columns, unique categories for categoricals).
- $E_i$ is the percentage of records in bin $i$ for the reference baseline.
- $A_i$ is the percentage of records in bin $i$ for the incoming logs.

**PSI Threshold Rules:**
- $PSI < 0.1$: No drift (Stable).
- $0.1 \le PSI < 0.25$: Moderate distribution shift (Log warnings triggered).
- $PSI \ge 0.25$: Significant data drift (Triggers the Auto-Retraining suggestion banner).

---

## 4. REST API Gateway & Authentication Control

All REST requests route through a FastAPI application secured by **JWT (JSON Web Token)** encryption:
- Passwords are encrypted using passlib's `sha256_crypt` algorithm.
- Session payloads include claims (`sub`: username, `role`: security level).
- Access tokens expire after 30 minutes.
- **Role-Based Access Control (RBAC)** verifies user tokens on protected endpoints, throwing HTTP 403 Forbidden for insufficient permissions (e.g. Viewers trying to upload incidents).
