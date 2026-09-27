# SOC Threat Incident Framework: Installation Guide

This guide details the step-by-step setup procedure to install and run the platform natively on your local development workstation.

---

## 🛠️ Step 1: Clone Repository and Configure Python

1. **Verify Python version**:
   Ensure you have **Python 3.11** or higher installed. Run the check:
   ```bash
   python --version
   ```
2. **Create a clean virtual environment**:
   ```bash
   python -m venv venv
   ```
3. **Activate the environment**:
   - **Windows (PowerShell)**:
     ```powershell
     .\venv\Scripts\Activate.ps1
     ```
   - **macOS / Linux**:
     ```bash
     source venv/bin/activate
     ```

---

## 📦 Step 2: Install Platform Dependencies

Install the requirements from `requirements.txt`.
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> [!NOTE]
> Under Windows environments, compilation of C++ boosters (e.g. LightGBM, CatBoost) requires a local compiler. If pip fails on these packages, install the [C++ Build Tools for Visual Studio](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

---

## ⚙️ Step 3: Configure Environment Settings

1. Copy the environment template:
   ```bash
   copy .env.example config/settings.env
   ```
2. Configure settings inside `config/settings.env` as needed. The defaults are pre-configured to launch SQLite and run locally:
   - `DATABASE_URL=sqlite:///database/db_sqlite.db`
   - `ENVIRONMENT=development`

---

## 💾 Step 4: Seed Threat Data & Initialize Databases

Generate the synthetic threat dataset, calculate advanced features, seed user accounts, and execute baseline model training:

1. **Simulate Raw Security Telemetry Log**:
   ```bash
   python src/data_generator.py
   ```
   *Generates 12,000 security incidents in `data/raw/cyber_incidents.csv`.*

2. **Run Data Preprocessing & Feature Engineering**:
   ```bash
   python src/feature_engineering.py
   ```
   *Applies deduplications, formats timestamps, calculates rolling features, and exports to `data/processed/cyber_incidents_processed.csv`.*

3. **Train Classifier Models**:
   ```bash
   python src/model_training.py
   ```
   *Runs RandomizedSearchCV cross-validation across 6 classifiers, selects the best F1 model (Gradient Boosting), and saves it to `models/best_model.joblib`.*

4. **Initialize and Seed User Access Controls**:
   ```bash
   python manage.py migrate
   python seed_db.py
   ```
   *Runs Django ORM database migrations, seeds default accounts: admin (Admin), analyst (Security Analyst), and viewer (Viewer).*

---

## 🚀 Step 5: Start Services Natively

1. **Launch Django REST API Backend Web Server**:
   ```bash
   python manage.py runserver 0.0.0.0:8000
   ```
2. **Launch SOC Streamlit Web Portal**:
   In a separate terminal shell (with the virtual environment activated):
   ```bash
   streamlit run app/dashboard.py --server.port 8501
   ```
3. **Inspect Services**:
   - Access the Streamlit portal: http://localhost:8501
   - View Django Admin Console: http://localhost:8000/admin/
   - View Health Vitals Status: http://localhost:8000/api/health/
