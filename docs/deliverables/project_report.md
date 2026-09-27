# Project Thesis Report: Advanced Threat Incident Analytics Framework

## Abstract
Modern Security Operations Centers (SOC) face immense volumes of telemetry logs, causing alert fatigue and delayed incident responses. This project develops an end-to-end Machine Learning-powered threat analytics and orchestration platform from scratch. By generating a synthetic dataset of 12,000 incidents, we calculate **14 custom security features** (including Attack Velocity and IP Reputation), and train 6 classifier algorithms. The champion model—**Gradient Boosting Classifier**—achieved a **90.63% F1-score**, correctly classifying incidents into Low, Medium, and High Risk. To address model transparency, we integrate local **SHAP feature attributions** explaining predictions in simple language. The platform is exposed via a secure **Django REST Framework API (JWT/RBAC) with a built-in admin dashboard**, visualized through an interactive **Streamlit dashboard**, monitored for data drift using the **Population Stability Index (PSI)**, and orchestrate using **Docker Compose** with PostgreSQL.

---

## 1. Introduction
With the growing scale of enterprise networks, manual threat triaging is no longer viable. Cyber-attacks like DDoS, SQL Injection, and Brute Force require sub-second detection and containment. Machine learning models offer automated classification but often lack interpretability and suffer from data drift. This project solves these challenges by building a production-ready SOC platform combining real-time classification, explainable AI (XAI), ARIMA forecasting, Django database audit logging, Django admin management, and drift monitoring.

---

## 2. Methodology & Feature Engineering
Incoming threat raw logs are cleaned, deduplicated, and passed to our feature engineering pipeline to compute 14 advanced behavioral indicators:
- **Velocity metrics**: Computes `Attack_Velocity` and `Failed_Login_Frequency` over 1-hour rolling windows.
- **Statistical anomalies**: Computes `Session_Duration_Anomaly` and `Geographic_Anomaly_Score` based on historical standard deviations.
- **Reputation profiles**: Builds historical risk weights for IP origins and country nodes (`IP_Reputation_Score`, `Country_Risk_Score`).
- **Unified Threat Index**: Calculates `Normalized_Risk_Score` on a scale of $[0.0, 10.0]$ as a composite indicator.

---

## 3. Machine Learning Performance Analysis
We evaluated 6 classifier architectures in a stratified 3-fold cross-validation grid search:
1. **Logistic Regression**: Linear baseline.
2. **Decision Tree**: Simple rule splits.
3. **Random Forest**: Bagged decision trees.
4. **XGBoost**: Gradient boosted decision trees.
5. **LightGBM**: Histogram-based boosted splits.
6. **CatBoost**: Categorically-optimized gradient boosting.
7. **Gradient Boosting**: Sequential boosted tree ensembles (Champion).

### Evaluation Metrics Summary
- **Accuracy**: Gradient Boosting achieved **90.80%** test accuracy.
- **F1-Score**: Gradient Boosting won champion status with a **90.63%** weighted F1-score.
- **Explainability**: SHAP (SHapley Additive exPlanations) values decompose prediction weights, explaining which telemetry values drove the risk calculation.

---

## 4. MLOps Lifecycle and Data Drift
To maintain model reliability, we implement:
- **Model Registry**: Archives versioned pipeline configurations with metadata.
- **Population Stability Index (PSI)**: Monitors incoming logs against baseline training sets. If the calculated PSI score crosses `0.25` on numerical columns, the platform flags significant data drift and prompts the administrator to trigger the retraining pipeline.

---

## 5. Conclusion & Future Directions
The platform successfully automates threat classification, explains prediction logic, alerts teams with generated incident tickets and PDFs, and monitors production data drift. Future expansions will focus on implementing distributed Apache Spark streaming adapters and integrating active learning loops for real-time model updates.
