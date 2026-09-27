# Project Presentation Slide Deck Outline

This file contains the slide-by-slide outline, visual guidelines, and talking points for presenting the project.

---

### Slide 1: Title & Project Overview
- **Title**: Advanced Threat Incident Analytics and Security Visualization Framework
- **Subtitle**: Enterprise-Grade SOC Analytics Platform with Machine Learning, Explainable AI, and MLOps Data Drift Monitoring
- **Presenters**: Group 1 Development Team
- **Talking Points**: Introduce the platform as a complete, containerized solution addressing alert fatigue and model degradation in Security Operations Centers.

---

### Slide 2: The Core Problem Statement
- **Key Bullet Points**:
  - Enterprise networks log millions of events daily, causing **alert fatigue**.
  - Traditional rule-based triggers generate excessive false positives.
  - ML models are often black-boxes, making security analysts skeptical of automated risk classification.
  - Distribution changes in network traffic (data drift) cause in-production model degradation.
- **Talking Points**: Outline the core challenges of modern SOC environments: scale, opacity of AI, and model decay.

---

### Slide 3: System Architecture Overview
- **Key Visuals**: Display the mermaid flow diagram from `README.md`.
- **Key Bullet Points**:
  - Ingestion: Synthetic telemetry data + dataset adapters.
  - Core Pipeline: 14 advanced engineered features.
  - Modeling: 6 comparative classifiers (Champion: Gradient Boosting).
  - API Gateway: FastAPI secured with JWT and Role-Based Access Control (RBAC).
  - Front-End Portal: Streamlit dashboard with live streaming mock alerts.
- **Talking Points**: Walk the audience through the multi-stage pipelines: data generation, validation, modeling, APIs, and the UI.

---

### Slide 4: Feature Engineering & Telemetry Science
- **Key Bullet Points**:
  - **Temporal & Frequency Features**: Hour, Weekend Flag, Attack Velocity.
  - **Anomalies Detection**: Session Duration Anomaly, impossible travel Geographic Anomaly.
  - **Profile Indices**: IP Reputation Score, Country Risk Score, and Device Risk Score.
  - **Unified Threat Index**: Mapped to target classes: Low, Medium, and High Risk.
- **Talking Points**: Explain how we calculate key behavioral indicators (such as Attack Velocity and IP Reputation) to feed raw logs into the classifiers.

---

### Slide 5: Machine Learning Models Evaluation
- **Key Visuals**: Display the performance matrix table.
- **Key Bullet Points**:
  - Trained 6 algorithms with Stratified Cross-Validation grid search.
  - **Gradient Boosting Classifier** selected as champion:
    - **F1-Score**: 90.63%
    - **Accuracy**: 90.80%
  - Saved model pipeline, metrics configuration, and feature names.
- **Talking Points**: Explain the model selection process. Discuss how we automatically train, compare metrics, and select the champion.

---

### Slide 6: Explainable AI (XAI) using SHAP
- **Key Visuals**: Display SHAP waterfall bar chart examples.
- **Key Bullet Points**:
  - Resolves black-box opacity issues by showing exact feature attribution weights.
  - Computes positive risk drivers (red) and negative risk mitigators (green).
  - Translates SHAP values into simple natural language explanations for SOC analysts.
- **Talking Points**: Demonstrate how a security analyst can inspect an incident's classification and immediately see the top three reasons behind the prediction.

---

### Slide 7: Time-Series Forecasting & Alerts
- **Key Visuals**: Display the Plotly forecasting line chart with shaded confidence intervals.
- **Key Bullet Points**:
  - Daily ARIMA model projections for the upcoming 30 days.
  - Displays cumulative weekly and monthly volume predictions with 95% confidence intervals.
  - High Risk triggers automatically generate case PDFs, write logs, and compile ServiceNow tickets.
- **Talking Points**: Explain how forecasting helps SOC managers plan shifts during predicted attack peaks, and how playbooks automate defensive routing.

---

### Slide 8: MLOps registry & Drift Monitoring
- **Key Bullet Points**:
  - **Model Registry**: Handles version control and allows promotional rollbacks.
  - **Population Stability Index (PSI)**: Monitors numerical and categorical feature shifts in real-time.
  - Suggests retraining when average PSI exceeds the drift threshold (`0.15`).
- **Talking Points**: Focus on system maintenance. Show how PSI monitors data drift to prevent model decay over time.

---

### Slide 9: Demo & Deployment Summary
- **Key Bullet Points**:
  - **Interactive Streamlit portal**: Admin user creations, logs explorer, live refreshes.
  - **FastAPI Backend Swagger**: REST endpoint checks.
  - **Docker Compose**: Containerized services linking PostgreSQL databases.
- **Talking Points**: Conclude with a live walkthrough demonstration. Highlight the readiness of the Docker orchestration.
