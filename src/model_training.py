"""
Advanced Machine Learning Model Training & Evaluation Pipeline
Trains and tunes 6 classifiers (Random Forest, XGBoost, LightGBM, CatBoost, 
Extra Trees, Gradient Boosting) using RandomizedSearchCV.
Generates ROC, Precision-Recall, Calibration, and Feature Importance curves.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Any

# Path configuration for direct execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support, 
    roc_auc_score, confusion_matrix, roc_curve, precision_recall_curve, auc
)

# Classifiers
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

from src.config import settings
from src.utils.logger import get_logger

logger = get_logger("model_training")

def load_processed_data(file_path: str = "data/processed/cyber_incidents_processed.csv") -> pd.DataFrame:
    """Loads the preprocessed and feature-engineered dataset. If missing, runs feature engineering."""
    if not os.path.exists(file_path):
        logger.warning(f"Processed dataset not found at '{file_path}'. Automatically executing feature engineering pipeline...")
        from src.feature_engineering import run_feature_engineering_pipeline
        return run_feature_engineering_pipeline(output_path=file_path)
    logger.info(f"Loading processed dataset from: {file_path}")
    return pd.read_csv(file_path)

def build_preprocessor(categorical_cols: List[str], numerical_cols: List[str]) -> ColumnTransformer:
    """Creates a ColumnTransformer for preprocessing numeric and categorical columns."""
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_cols)
        ]
    )
    return preprocessor

def get_tuning_grids() -> Dict[str, Dict[str, Any]]:
    """Returns hyperparameter tuning search spaces for each model type."""
    return {
        "Random Forest": {
            "classifier__n_estimators": [50, 100],
            "classifier__max_depth": [6, 10, None],
            "classifier__min_samples_split": [2, 5]
        },
        "XGBoost": {
            "classifier__n_estimators": [50, 100],
            "classifier__max_depth": [4, 6, 8],
            "classifier__learning_rate": [0.05, 0.1, 0.2]
        },
        "LightGBM": {
            "classifier__n_estimators": [50, 100],
            "classifier__max_depth": [4, 8, -1],
            "classifier__learning_rate": [0.05, 0.1]
        },
        "CatBoost": {
            "classifier__iterations": [50, 100],
            "classifier__depth": [4, 6],
            "classifier__learning_rate": [0.05, 0.1]
        },
        "Extra Trees": {
            "classifier__n_estimators": [50, 100],
            "classifier__max_depth": [6, 10, None]
        },
        "Gradient Boosting": {
            "classifier__n_estimators": [50, 100],
            "classifier__max_depth": [3, 5],
            "classifier__learning_rate": [0.05, 0.1]
        }
    }

def generate_curves(trained_models: Dict[str, Pipeline], X_test: pd.DataFrame, y_test: pd.Series, output_dir: str = "models") -> None:
    """Generates and saves ROC, PR, and Calibration curves for all trained models."""
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. ROC Curves
    plt.figure(figsize=(8, 6))
    for name, pipeline in trained_models.items():
        y_prob = pipeline.predict_proba(X_test)
        # For multiclass, average ROC curve (One-vs-Rest Macro)
        # Let's binarize y_test to calculate multiclass ROC curves
        # For simple plotting, we can plot the ROC of the positive class if it was binary,
        # or aggregate Macro ROC. Let's calculate the macro ROC by averaging micro/macro values
        # or simply evaluate class 2 (High Risk) as an indicator of threat
        # To make it robust and easy to visualize, we plot the ROC for the 'High Risk' class (Class 2)
        fpr, tpr, _ = roc_curve((y_test == 2).astype(int), y_prob[:, 2])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, label=f'{name} (High Risk AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], 'k--', label='Random Guess')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curves (High Risk Class)')
    plt.legend(loc="lower right")
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "roc_curves.png"))
    plt.close()

    # 2. Precision-Recall Curves
    plt.figure(figsize=(8, 6))
    for name, pipeline in trained_models.items():
        y_prob = pipeline.predict_proba(X_test)
        precision, recall, _ = precision_recall_curve((y_test == 2).astype(int), y_prob[:, 2])
        pr_auc = auc(recall, precision)
        plt.plot(recall, precision, label=f'{name} (High Risk AUC = {pr_auc:.2f})')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curves (High Risk Class)')
    plt.legend(loc="lower left")
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "pr_curves.png"))
    plt.close()

    # 3. Calibration Curves (Reliability Diagrams)
    plt.figure(figsize=(8, 6))
    for name, pipeline in trained_models.items():
        y_prob = pipeline.predict_proba(X_test)[:, 2] # Probability of High Risk
        prob_true, prob_pred = calibration_curve((y_test == 2).astype(int), y_prob, n_bins=10)
        plt.plot(prob_pred, prob_true, marker='o', label=name)
    plt.plot([0, 1], [0, 1], 'k--', label='Perfect Calibration')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Mean Predicted Probability (High Risk)')
    plt.ylabel('Fraction of Positives')
    plt.title('Calibration Curves (Reliability Diagram)')
    plt.legend(loc="lower right")
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "calibration_curves.png"))
    plt.close()

def save_feature_importance_plot(pipeline: Pipeline, feature_names: List[str], model_name: str, output_dir: str = "models") -> None:
    """Extracts and plots feature importances from the champion model."""
    try:
        classifier = pipeline.named_steps['classifier']
        preprocessor = pipeline.named_steps['preprocessor']
        
        # Get feature names after one-hot encoding
        cat_encoder = preprocessor.named_transformers_['cat']
        cat_features_encoded = cat_encoder.get_feature_names_out().tolist()
        num_features = preprocessor.transformers[0][2]
        all_features_encoded = num_features + cat_features_encoded
        
        # Check if classifier has feature importances
        if hasattr(classifier, 'feature_importances_'):
            importances = classifier.feature_importances_
            
            # Map importances to encoded features
            fi_df = pd.DataFrame({
                'Feature': all_features_encoded,
                'Importance': importances
            }).sort_values(by='Importance', ascending=False).head(15) # top 15
            
            plt.figure(figsize=(10, 6))
            sns.barplot(data=fi_df, x='Importance', y='Feature', palette='Blues_r')
            plt.title(f'Top 15 Feature Importances - {model_name}')
            plt.xlabel('Relative Importance')
            plt.ylabel('Features')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, "feature_importance.png"))
            plt.close()
            logger.info("Saved feature importance visualization plot.")
    except Exception as e:
        logger.warning(f"Could not generate feature importance plot: {str(e)}")

def run_ml_pipeline() -> Pipeline:
    """Runs the advanced ML training pipeline with tuning, validation, and curve exports."""
    # 1. Load data
    df = load_processed_data()
    
    # Define features and labels
    categorical_cols = ['Attack_Type', 'Protocol', 'Port', 'Device', 'Country', 'User_Role', 'Auth_Method']
    numerical_cols = [
        'Failed_Login_Count', 'Hour', 'Weekend_Flag', 'Session_Duration', 
        'Attack_Velocity', 'Failed_Login_Frequency', 'Historical_Threat_Count',
        'Threat_Density', 'IP_Reputation_Score', 'Rolling_Incident_Average',
        'Session_Duration_Anomaly', 'Geographic_Anomaly_Score', 
        'User_Behaviour_Anomaly_Score', 'Login_Time_Anomaly', 'Attack_Burst_Detection',
        'Device_Risk_Score', 'Country_Risk_Score'
    ]
    
    # Map labels: Low Risk=0, Medium Risk=1, High Risk=2
    risk_mapping = {"Low Risk": 0, "Medium Risk": 1, "High Risk": 2}
    inverse_risk_mapping = {v: k for k, v in risk_mapping.items()}
    target_names = ["Low Risk", "Medium Risk", "High Risk"]
    
    y = df['Risk_Level'].map(risk_mapping)
    X = df[categorical_cols + numerical_cols]
    
    # Extract feature names list
    feature_names = X.columns.tolist()
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Preprocessor
    preprocessor = build_preprocessor(categorical_cols, numerical_cols)
    
    # Candidate models
    models = {
        "Random Forest": RandomForestClassifier(random_state=42),
        "XGBoost": XGBClassifier(random_state=42, eval_metric='mlogloss'),
        "LightGBM": LGBMClassifier(random_state=42, verbose=-1),
        "CatBoost": CatBoostClassifier(random_state=42, verbose=0),
        "Extra Trees": ExtraTreesClassifier(random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42)
    }
    
    grids = get_tuning_grids()
    cv_strategy = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    
    trained_pipelines: Dict[str, Pipeline] = {}
    model_metrics: Dict[str, Any] = {}
    
    # 4. Train, Tune and Evaluate each model
    for model_name, clf in models.items():
        logger.info(f"Tuning and training: {model_name}...")
        raw_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', clf)
        ])
        
        search = RandomizedSearchCV(
            estimator=raw_pipeline,
            param_distributions=grids[model_name],
            n_iter=2,
            cv=cv_strategy,
            scoring='f1_weighted',
            random_state=42,
            n_jobs=1
        )
        
        search.fit(X_train, y_train)
        best_pipeline = search.best_estimator_
        trained_pipelines[model_name] = best_pipeline
        
        # Evaluate
        y_pred = best_pipeline.predict(X_test)
        y_prob = best_pipeline.predict_proba(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        
        try:
            roc_auc = roc_auc_score(y_test, y_prob, multi_class='ovr', average='weighted')
        except Exception:
            roc_auc = 0.0
            
        cm = confusion_matrix(y_test, y_pred)
        
        model_metrics[model_name] = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "roc_auc": float(roc_auc),
            "confusion_matrix": cm.tolist()
        }
        
        logger.info(f"{model_name} -> F1-Score: {f1:.4f}, Accuracy: {accuracy:.4f}")
        
        # Save individual confusion matrix
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=target_names, yticklabels=target_names)
        plt.title(f'Confusion Matrix - {model_name}')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.tight_layout()
        plt.savefig(os.path.join("models", f"{model_name.lower().replace(' ', '_')}_cm.png"))
        plt.close()

    # 5. Generate validation curves
    logger.info("Generating verification curves (ROC, PR, Calibration)...")
    generate_curves(trained_pipelines, X_test, y_test)

    # 6. Select and persist the best-performing model based on F1-Score
    best_model_name = max(model_metrics, key=lambda k: model_metrics[k]["f1_score"])
    logger.info(f"Champion Model: {best_model_name} (F1: {model_metrics[best_model_name]['f1_score']:.4f})")
    
    best_pipeline = trained_pipelines[best_model_name]
    
    # Save Feature Importance plot of the champion model
    save_feature_importance_plot(best_pipeline, feature_names, best_model_name)
    
    # Save best model pipeline
    os.makedirs("models", exist_ok=True)
    joblib.dump(best_pipeline, settings.MODEL_PATH)
    logger.info(f"Saved champion pipeline to '{settings.MODEL_PATH}'")
    
    # Save performance metrics summary
    summary_metrics = {
        "best_model_name": best_model_name,
        "risk_mapping": risk_mapping,
        "inverse_risk_mapping": inverse_risk_mapping,
        "feature_names": feature_names,
        "metrics": model_metrics
    }
    with open(settings.METRICS_PATH, "w") as f:
        json.dump(summary_metrics, f, indent=4)
    logger.info(f"Saved performance metrics summary to '{settings.METRICS_PATH}'")
    
    return best_pipeline

if __name__ == "__main__":
    run_ml_pipeline()
