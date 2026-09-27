# SOC Threat Incident Framework: User Manual

This manual provides an operational guide for SOC analysts, security managers, and viewers using the interactive Streamlit dashboard.

---

## 🔒 1. Platform Login

1. Open your web browser and navigate to the Streamlit portal (default local URL: http://localhost:8501).
2. You will be greeted with the **SOC Enterprise Login Portal** secure lock screen.
3. Enter your assigned username and password. On clean installations, use one of the seeded accounts:
   - **Administrator**: `admin` / `admin123`
   - **Security Analyst**: `analyst` / `analyst123`
   - **Viewer**: `viewer` / `viewer123`
4. Click **Access SOC Platform** to enter.

---

## 📊 2. Main Navigation and Features

Select tabs from the left-side navigation panel to access platform functions based on your Role-Based Access Control (RBAC) privileges:

### 💼 Tab 1: SOC Overview Dashboard
*Displays system-wide statistics.*
- **KPI Metrics**: Total alerts count, High Risk counts, block rates, and origin countries.
- **Visual Charts**: Interactive line trends, severity donut breakdowns, top attack counts, and geographical choropleths.
- **Live Feed Simulation**: Check the **Enable Live Data Feed Simulation** box to inject mock network alerts in real-time, auto-refreshing the dashboard graphs every 3 seconds.

### 🔍 Tab 2: Security Logs Explorer
*Allows searching, filtering, and exporting logs.*
- **Filters**: Filter alerts by Attack Type and Severity using sidebar controls.
- **Exporting**: Click **Export Filtered Logs to CSV** to download files locally.

### 🔮 Tab 3: Threat Prediction Portal (Playbooks)
*Calculates threat risks and shows actionable playbooks.*
- **Telemetry Form**: Input raw packet variables (Port, failed logins, session duration, user organizational role, authentication method, reputation score).
- **Run Prediction**: Calculates risk (`Low Risk`, `Medium Risk`, or `High Risk`) alongside class probability distributions.
- **High-Risk Alerts**: Detections instantly generate PDF compliance reports, log database records, and issue mock ServiceNow tickets.

### 🛡️ Tab 4: SHAP Explainability Portal
*Inspects the decision parameters of the classifier.*
- Computes local **SHAP attribution** for the last predicted incident.
- Renders a horizontal bar chart demonstrating which parameters drove risk up (red bars) or down (green bars).
- Displays plain-English descriptions explaining the classification.

### 🔮 Tab 5: Time-Series Forecasting
*Provides attack frequency forecasts for SOC capacity planning.*
- Renders 30-day projected alert frequency curves.
- Displays weekly and monthly cumulative alert volume projections alongside a 95% confidence interval range.

### 🤖 Tab 6: MLOps Drift & Registry (Admin / Analyst Only)
*Maintains model performance checks.*
- **Model Registry**: Lists registered model versions and F1 scores. Allows administrators to promote any registered version to active champion status.
- **Data Drift Monitor**: Calculates the **Population Stability Index (PSI)** for numerical features, flagging feature drift if values cross threshold limits.

---

## 🛠️ 3. Django Administration Console (Admin Only)

Administrators have access to the built-in **Django Admin Panel** at http://localhost:8000/admin/.

1. **Authentication**: Use superuser accounts or standard Admin credentials (`admin` / `admin123`).
2. **Features**:
   - **User Management**: Add, modify, or delete user accounts, reset passwords, and assign groups.
   - **Compliance Review**: Browse and search the central `Audit Logs` table to trace user queries and actions.
   - **Threat Logs Inspection**: Directly query or search through the raw `Incident` records table and past `Prediction Logs` details.
