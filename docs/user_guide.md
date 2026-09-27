# User & Deployment Guide

This guide covers running the framework locally, navigating the dashboards, and deploying the platform to production clouds (Streamlit Community Cloud and Render).

---

## 1. Local Setup and Execution

### System Requirements
- Python 3.8 to 3.11
- Pip package manager

### Step-by-Step Installation
1. **Clone or Download the Project**:
   Ensure you have the directory structure and files in place on your workspace.
2. **Create a Virtual Environment** (Highly Recommended):
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Generate Raw Dataset & Process Data**:
   ```bash
   python src/data_generator.py
   python src/preprocessing.py
   python src/feature_engineering.py
   ```
5. **Train Machine Learning Models**:
   ```bash
   python src/model_training.py
   ```
6. **Launch Streamlit Dashboard App**:
   ```bash
   streamlit run app/dashboard.py
   ```
   The dashboard will automatically open in your default browser at `http://localhost:8501`.

---

## 2. Dashboard Navigation and Features

The application contains five primary pages accessible via the left sidebar:

- **📊 Dashboard Overview**:
  - Displays real-time KPIs (total incidents, high risk metrics, firewalls block rates, and top attacker IP).
  - Contains chronological line graphs showing attack frequencies.
  - Interactive donut charts break down reported severities.
  - Visualizes global concentration metrics on a world map.
  - Heatmaps outline attack types across communication protocols.
- **🔍 Incident Data Explorer**:
  - Explores individual security events.
  - Filter logs dynamically using the sidebar (date ranges, origin countries, severity levels, attack type).
  - Search fields isolate records from specific IP addresses.
  - Download options export log views as CSV or summary executive reports in PDF.
- **🔮 Real-Time Threat Predictor**:
  - Manually input incident metrics (attack type, protocol, port, device, origin, failed logins, temporal patterns, and IP history reputation).
  - Classifies the event risk dynamically using the machine learning classifier pipeline.
  - Outputs actionable playbook checklists (High/Medium/Low risk controls) and probability histograms.
  - Exports a custom, formal PDF Case File for threat investigation logging.
- **📈 ML Model Performance Analytics**:
  - Compares evaluation metrics (Accuracy, Precision, Recall, F1, ROC-AUC) across Logistic Regression, Decision Tree, Random Forest, and XGBoost.
  - Displays confusion matrix plots for the active champion model.
  - Displays correlation scatters comparing suspicious IP scores against final risks.
- **📄 Reports Centre**:
  - Central location to compile and download PDF/CSV compliance-ready reports.

---

## 3. Deploying to Streamlit Community Cloud

Streamlit Community Cloud is a free hosting platform designed directly for Streamlit apps.

### Deployment Process
1. **Push Code to GitHub**:
   Initialize a git repository in your project directory and push it to GitHub:
   ```bash
   git init
   git add .
   git commit -m "Initial commit of security framework"
   git remote add origin <your-github-repo-url>
   git branch -M main
   git push -u origin main
   ```
2. **Log into Streamlit Share**:
   Go to [share.streamlit.io](https://share.streamlit.io/) and log in with your GitHub account.
3. **Deploy App**:
   - Click **New App**.
   - Select your repository, the `main` branch, and set the main file path to `app/dashboard.py`.
   - Click **Deploy!**
   Streamlit will automatically read `requirements.txt`, install packages, compile the synthetic dataset on startup, and serve the dashboard globally.

---

## 4. Deploying to Render

Render is a modern cloud hosting platform. Since Streamlit is a web process, we can host it as a web service.

### Deployment Method: Web Service
1. **Create Account**:
   Sign in at [render.com](https://render.com) and link your GitHub profile.
2. **Configure New Web Service**:
   - Click **New +** and select **Web Service**.
   - Connect the repository containing this project.
3. **Build & Start Settings**:
   - **Environment**: `Python` (or `Docker` if utilizing custom container builds)
   - **Build Command**: `pip install -r requirements.txt && python src/data_generator.py && python src/preprocessing.py && python src/feature_engineering.py && python src/model_training.py`
     - *This generates the raw dataset, preprocesses it, and trains the model during the build phase so the application has it ready on startup.*
   - **Start Command**: `streamlit run app/dashboard.py --server.port $PORT --server.address 0.0.0.0`
4. **Select Plan**:
   Choose the Free tier or a suitable instance plan.
5. **Deploy**: Click **Create Web Service**. Render will build and deploy the app, providing a public URL (e.g. `https://my-app.onrender.com`).
