# SOC Threat Incident Framework: Developer Guide

This document acts as a technical reference guide for software engineers, machine learning engineers, and data engineers extending the codebase.

---

## 🏛️ System & Class Diagram Architecture

```mermaid
classDiagram
    class Settings {
        +DATABASE_URL : str
        +JWT_SECRET_KEY : str
        +RETRAIN_DRIFT_THRESHOLD : float
        +get(key, default)
    }

    class DatabaseManager {
        +initialize_database()
        +get_db_api()
        +db_create_user()
        +db_add_incident()
        +db_add_prediction_log()
    }

    class IncidentPredictor {
        +pipeline : Pipeline
        +risk_labels : Dict
        +load_model()
        +predict_incident(data)
    }

    class ThreatExplainer {
        +pipeline : Pipeline
        +explain_instance(df, pred_idx)
    }

    class DriftDetector {
        +threshold : float
        +calculate_psi(expected, actual)
        +analyze_dataset_drift(ref_df, target_df)
    }

    class ModelRegistry {
        +registry_dir : str
        +register_model(version, metrics, features)
        +promote_to_champion(version)
    }

    IncidentPredictor --> Settings : reads config
    DatabaseManager --> Settings : reads config
    DriftDetector --> Settings : reads config
    ModelRegistry --> Settings : reads config
    ThreatExplainer --> IncidentPredictor : wraps pipeline
```

---

## 💾 Database Schema (ER Diagram)

```mermaid
erDiagram
    USERS {
        int id PK
        string username
        string password_hash
        string role
        datetime created_at
    }

    INCIDENTS {
        int id PK
        datetime timestamp
        string source_ip
        string destination_ip
        string attack_type
        string protocol
        int port
        string severity
        string status
        string country
        string device
        string action_taken
        int failed_login_count
        float session_duration
    }

    PREDICTION_LOGS {
        int id PK
        datetime timestamp
        string source_ip
        string dest_ip
        string attack_type
        string risk_level
        float confidence
        string recommendation
        text features_json
    }

    AUDIT_LOGS {
        int id PK
        datetime timestamp
        string username
        string action
        string ip_address
    }
```

---

## 🤖 How to Add a New Machine Learning Model

To add a new model pipeline to the comparative cross-validation grid search:

1. **Open `src/model_training.py`**.
2. Locate the model configuration grids definition in `run_ml_pipeline()`:
   ```python
   models = {
       "Random Forest": RandomForestClassifier(random_state=42),
       "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42),
       # ADD YOUR NEW ESTIMATOR HERE:
       "SVR": SVC(probability=True, random_state=42)
   }
   ```
3. Define its hyperparameter grid in the `grids` dictionary:
   ```python
   grids = {
       "SVR": {
           "classifier__C": [0.1, 1.0, 10.0],
           "classifier__kernel": ["rbf", "linear"]
       }
   }
   ```
4. Run the training command:
   ```bash
   python src/model_training.py
   ```
   The training loop will automatically fit your model, compute scores, output comparative bar plots, compare it against Gradient Boosting, and serialize the best pipeline model to `models/best_model.joblib`.

---

## 🛠️ Extending Django REST Gateways

To add a new API endpoint to the Django REST layer:

1. **Add Model fields**: Update `soc_app/models.py`. Run:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```
2. **Configure Serializer**: Open `soc_app/serializers.py` and declare a new serializer subclass mapping the input validation requirements.
3. **Write View logic**: Open `soc_app/views.py` and create an APIView or ViewSet class. Apply permission restrictions (e.g., `permission_classes = [IsSecurityAnalystOrAdmin]`).
4. **Map URL Route**: Add the path mapping to the list inside `soc_project/urls.py`.
5. **Run tests**:
   ```bash
   python manage.py test
   ```
