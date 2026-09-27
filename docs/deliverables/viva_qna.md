# Viva Questions & Answers

This guide compiles 15 key academic and professional questions (with detailed answers) to prepare for viva examinations or technical reviews.

---

### Q1: What is the primary objective of this project?
**Answer**: The primary goal is to build an end-to-end, enterprise-grade threat analytics platform that automates security incident risk classification, explains prediction drivers using SHAP values, forecasts future incident volumes, monitors data drift via the Population Stability Index (PSI), and integrates security playbooks via REST APIs.

---

### Q2: Why did you use F1-Score instead of Accuracy to select the champion model?
**Answer**: Classification datasets in cybersecurity are heavily imbalanced (the vast majority of logs are Low Risk, while High Risk attacks represent a very small percentage). If we use standard accuracy, a naive model classifying everything as Low Risk would score high accuracy but fail to detect critical exploits. The F1-score balances Precision and Recall, making it the standard metric for class-imbalanced models.

---

### Q3: Explain the math behind the Population Stability Index (PSI) used in drift detection.
**Answer**: PSI evaluates distribution changes between reference baseline data ($E$) and target actual logs ($A$) over $B$ bins:

$$PSI = \sum_{i=1}^{B} \left( (A_i - E_i) \times \ln\left(\frac{A_i}{E_i}\right) \right)$$

- $PSI < 0.1$ indicates no distribution change.
- $0.1 \le PSI < 0.25$ indicates moderate drift.
- $PSI \ge 0.25$ indicates significant drift, suggesting model retraining is required.

---

### Q4: How does SHAP (SHapley Additive exPlanations) explain threat predictions?
**Answer**: SHAP is based on cooperative game theory. It treats feature values as players in a coalition. The "game" is predicting the class probability, and the features' contributions (SHAP values) are calculated as the average marginal change when adding a feature to all possible sub-coalitions, ensuring local accuracy and consistency.

---

### Q5: What is the benefit of using ARIMA for time-series forecasting in this project?
**Answer**: ARIMA (AutoRegressive Integrated Moving Average) is a robust statistical forecasting model. In our platform, we fit `ARIMA(1,1,1)` to predict daily alert frequencies. This enables SOC managers to anticipate attack volume spikes and optimize analyst shifts during projected high-volume periods.

---

### Q6: How does the platform handle Role-Based Access Control (RBAC)?
**Answer**: RBAC is implemented using **Django REST Framework permission classes** (e.g. `IsAdmin`, `IsSecurityAnalystOrAdmin`, `IsViewerOrAbove`) which check roles stored in JWT user profiles. Claims are verified automatically by **SimpleJWT** middleware. Roles include:
- **Admin**: Full read/write access + user registration + MLOps version promotions.
- **Security Analyst**: Can run threat predictions, view dashboards, check SHAP plots, and export reports.
- **Viewer**: Read-only access to overview dashboards and forecasting trends. All REST write routes (uploads/predictions) are blocked.

---

### Q7: Explain why you modified the password hashing algorithm to `sha256_crypt`?
**Answer**: Python 3.14 (the pre-release/latest version running on our execution server) has binary compatibility issues compiling the C-libraries for `bcrypt` and `passlib`. Using `sha256_crypt` (which runs on pure python and hashlib) bypasses compiling errors on Windows while maintaining compliance-grade hashing standards.

---

### Q8: What does the feature "IP_Reputation_Score" measure?
**Answer**: It measures the historical severity profile of a specific `Source_IP` by calculating the ratio of blocked or isolated actions against the total actions logged for that IP. IPs with higher ratios score close to `10.0`, representing high reputation risk.

---

### Q9: How is the "Attack_Velocity" feature calculated, and what does it detect?
**Answer**: It is a rolling window calculation that counts the number of incidents originating from the same `Source_IP` in the past 1 hour. This feature helps identify fast, automated threat activity, such as brute-force log attempts or port scan sweeps.

---

### Q10: How does the model pipeline handle mixed numerical and categorical telemetry?
**Answer**: We implement a scikit-learn `Pipeline` utilizing a `ColumnTransformer`:
- **Numerical columns** are scaled using `StandardScaler` to normalize distributions.
- **Categorical columns** are encoded using `OneHotEncoder` with `handle_unknown='ignore'` to convert text attributes into binary flags safely.

---

### Q11: What occurs in the backend when a "High Risk" threat is predicted?
**Answer**: A threat playbook is executed:
1. Generates a formal compliance case PDF in the `alerts/` folder.
2. Commits a critical warning audit log to the database.
3. Simulates sending an encrypted alert email to security responders.
4. Generates a mock ticketing system incident report (JSON) matching ServiceNow/Jira specifications.

---

### Q12: Why did you separate the REST API and Streamlit dashboard into separate containers?
**Answer**: This represents a standard **Microservices Architecture**. Isolating the backend APIs and frontend UI ensures that if the UI crashes due to user load, the core threat validation API and databases remain up. It also allows developers to scale API containers independently behind a load balancer.

---

### Q13: How does the "Attack_Burst_Detection" feature work?
**Answer**: It checks if the alert frequency within a rolling 10-minute window exceeds three standard deviations from the historical mean. If so, it flags a burst event (`1`), detecting floods or DDoS attempts.

---

### Q14: How does the platform detect impossible travel anomalies?
**Answer**: The **Geographic Anomaly Score** measures geographical travel velocity. By comparing the distance between subsequent incident logs for the same user against the time elapsed, the system flags logins originating from locations that are physically impossible to travel to in that timeframe.

---

### Q15: How does the MLOps Registry handle model promotion?
**Answer**: When a model is promoted:
1. The registry loads the selected model's versioned binary (`model_v_X.Y.Z.joblib`).
2. It overwrites `best_model.joblib` in the production folder.
3. It updates `model_metrics.json` with the promoted model's parameters and metrics, making it the active model for incoming API requests.
