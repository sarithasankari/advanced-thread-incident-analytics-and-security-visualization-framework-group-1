# FastAPI REST API Swagger Specification

This document details the route endpoints, parameters, JSON payload schemas, and headers required to interact with the security API.

---

## 🔑 Authentication Header
All protected API endpoints require a bearer authorization header. Tokens are obtained via the `/api/auth/token` route:
```http
Authorization: Bearer <YOUR_JWT_ACCESS_TOKEN>
```

---

## 🛣️ API Endpoints Index

| Method | Route | Description | Access Level |
| :--- | :--- | :--- | :--- |
| **POST** | `/api/auth/register` | Registers a new security account | `Admin` |
| **POST** | `/api/auth/token` | Exchanges username/password for a JWT token | Public |
| **POST** | `/api/incidents/upload` | Validates and ingests a list of threat logs | `Admin`, `Security Analyst` |
| **POST** | `/api/predict` | Computes threat risk and executes playbooks if High | `Admin`, `Security Analyst` |
| **POST** | `/api/predict/explain`| Computes threat risk and yields local SHAP impacts | `Admin`, `Security Analyst` |
| **GET** | `/api/forecast` | Returns 30-day projected incident counts | `Admin`, `Security Analyst`, `Viewer` |
| **GET** | `/api/health` | Returns connectivity status (databases, ML loaders) | Public |

---

## 📝 Request / Response Payloads Example

### 1. Token Exchange (`POST /api/auth/token`)
- **Content-Type**: `application/x-www-form-urlencoded`
- **Request Parameters**:
  ```ini
  username=analyst
  password=analyst123
  ```
- **Response Example (`200 OK`)**:
  ```json
  {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer"
  }
  ```

### 2. Real-Time Risk Prediction (`POST /api/predict`)
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Bearer <token>`
- **Request Body**:
  ```json
  {
      "Attack_Type": "SQL Injection",
      "Protocol": "TCP",
      "Port": 80,
      "Device": "WAF",
      "Country": "US",
      "Failed_Login_Count": 1,
      "Hour": 14,
      "Weekend_Flag": 0,
      "Attack_Frequency": 4,
      "Suspicious_IP_Score": 1.5,
      "Session_Duration": 45.0,
      "User_Role": "Standard Employee",
      "Auth_Method": "Password"
  }
  ```
- **Response Example (`200 OK`)**:
  ```json
  {
      "predicted_risk_level": "High Risk",
      "confidence_pct": 98.42,
      "recommendation": "IMMEDIATE RESPONSE: Isolate destination IP 10.100.1.25. Block origin IP via WAF firewall rules. Alert SOC dispatcher.",
      "all_probabilities": {
          "Low Risk": 0.23,
          "Medium Risk": 1.35,
          "High Risk": 98.42
      },
      "alert_details": {
          "pdf_path": "alerts/alert_20260804_134718_192_168_1_211.pdf",
          "email_simulated": true,
          "ticket_path": "alerts/ticket_20260804_134718_192_168_1_211.json",
          "ticket_id": "TKT-20260804_134718-4982"
      }
  }
  ```

### 3. Prediction Interpretability (`POST /api/predict/explain`)
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Bearer <token>`
- **Request Body**: (Same telemetry input schema as `/api/predict`)
- **Response Example (`200 OK`)**:
  ```json
  {
      "prediction": {
          "predicted_risk_level": "High Risk",
          "confidence_pct": 98.42,
          "recommendation": "..."
      },
      "shap_explanation": {
          "success": true,
          "feature_impacts": {
              "Failed_Login_Count": 3.82,
              "Suspicious_IP_Score": 2.11,
              "Attack_Frequency": 1.45,
              "Port": -0.84
          },
          "explanations": [
              "Failed_Login_Count (value: 1.0) increased threat risk significantly.",
              "Suspicious_IP_Score (value: 1.5) contributed positively to the threat classification.",
              "Port (value: 80.0) reduced classification risk slightly."
          ]
      }
  }
  ```
