"""
Explainable AI (XAI) Module
Integrates SHAP to explain machine learning classifier predictions.
Provides local explanation attributions, global importance, and plain-English reasons.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Tuple

# Path configuration for direct execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import shap
from sklearn.pipeline import Pipeline
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger("explainability")

class ThreatExplainer:
    """Uses SHAP to provide local and global interpretability for threat classifications."""

    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline
        self.preprocessor = pipeline.named_steps['preprocessor']
        self.classifier = pipeline.named_steps['classifier']
        self.explainer: Any = None
        self.feature_names: List[str] = []
        self._initialize_explainer()

    def _initialize_explainer(self) -> None:
        """Fits the SHAP explainer on the preprocessor-transformed feature spaces."""
        try:
            # Reconstruct feature names after column transformations
            cat_encoder = self.preprocessor.named_transformers_['cat']
            cat_features = cat_encoder.get_feature_names_out().tolist()
            num_features = self.preprocessor.transformers[0][2]
            self.feature_names = num_features + cat_features
            
            # Initialize explainer on tree-based models or standard explainer
            # We use a mock/background dataset of size 50 to initialize TreeExplainer quickly
            # fit on a dummy array or use standard explainer
            self.explainer = shap.Explainer(self.classifier)
            logger.info("SHAP Explainer initialized successfully.")
        except Exception as e:
            logger.warning(f"Failed to initialize standard SHAP explainer: {str(e)}. Falling back to tree-specific explainer.")
            try:
                self.explainer = shap.TreeExplainer(self.classifier)
                logger.info("SHAP TreeExplainer initialized as fallback.")
            except Exception as e2:
                logger.warning(f"TreeExplainer failed: {str(e2)}. Initializing model-agnostic Explainer.")
                try:
                    # Fallback to model-agnostic Explainer with predict_proba and a small background
                    background = np.zeros((1, len(self.feature_names)))
                    self.explainer = shap.Explainer(self.classifier.predict_proba, background)
                    logger.info("SHAP model-agnostic Explainer initialized successfully.")
                except Exception as e3:
                    logger.error(f"Failed to initialize any SHAP explainer: {str(e3)}", exc_info=True)
                    self.explainer = None

    def explain_instance(self, incident_df: pd.DataFrame, predicted_class_idx: int) -> Dict[str, Any]:
        """
        Calculates local SHAP feature attributions for a single prediction row.
        Returns sorted dictionary of feature impacts and plain-English reasons.
        """
        if self.explainer is None:
            return self._get_fallback_explanations(incident_df)

        try:
            # Align columns: pad any missing columns expected by the preprocessor with 0.0
            feature_names = None
            if hasattr(self.preprocessor, 'feature_names_in_'):
                feature_names = self.preprocessor.feature_names_in_
            elif hasattr(self.pipeline, 'feature_names_in_'):
                feature_names = self.pipeline.feature_names_in_
                
            if feature_names is not None:
                incident_df = incident_df.copy()
                for col in feature_names:
                    if col not in incident_df.columns:
                        incident_df[col] = 0.0
                # Reorder columns to match the training feature schema
                incident_df = incident_df[feature_names]

            # 1. Transform raw DataFrame through the pipeline preprocessor
            transformed_arr = self.preprocessor.transform(incident_df)
            
            # 2. Compute SHAP values
            shap_values = self.explainer(transformed_arr)
            
            # 3. Handle multidimensional outputs (multiclass classification SHAP values shape: [samples, features, classes] or list of [samples, features])
            # If shap_values is a list of arrays (one per class), extract the array for the predicted class
            if isinstance(shap_values, list):
                class_shap = shap_values[predicted_class_idx][0] # first sample
            elif len(shap_values.shape) == 3:
                class_shap = shap_values.values[0, :, predicted_class_idx]
            else:
                class_shap = shap_values.values[0] # binary fallback

            # 4. Map back to feature names
            impact_map = {}
            for name, val in zip(self.feature_names, class_shap):
                # Group encoded categories together for simple user readability
                clean_name = name
                if "_" in name and name.split("_")[0] in ["Attack", "Protocol", "Device", "Country", "User", "Auth"]:
                    # E.g. Attack_Type_DDoS -> Attack Type: DDoS
                    parts = name.split("_")
                    if len(parts) >= 3:
                        clean_name = f"{parts[0]} {parts[1]}: {' '.join(parts[2:])}"
                impact_map[clean_name] = float(val)

            # Sort features by absolute impact
            sorted_impacts = sorted(impact_map.items(), key=lambda x: abs(x[1]), reverse=True)
            
            # Separate positive and negative drivers
            positives = [(k, v) for k, v in sorted_impacts if v > 0.0][:3]
            negatives = [(k, v) for k, v in sorted_impacts if v < 0.0][:3]

            # Generate natural language reasons
            reasons = self._generate_reasons(positives, negatives, incident_df)

            return {
                "success": True,
                "feature_impacts": impact_map,
                "top_positive_drivers": positives,
                "top_negative_drivers": negatives,
                "explanations": reasons
            }

        except Exception as e:
            logger.error(f"Error executing SHAP explanation instance: {str(e)}", exc_info=True)
            return self._get_fallback_explanations(incident_df)

    def _generate_reasons(self, positives: List[Tuple[str, float]], negatives: List[Tuple[str, float]], df: pd.DataFrame) -> List[str]:
        """Translates numerical SHAP attributions into clear, logical security operations summaries."""
        reasons = []
        
        # Explain positive drivers
        for feat, val in positives:
            if "Failed_Login_Count" in feat or "Failed Login" in feat:
                val_logins = df.get("Failed_Login_Count", [0])[0]
                reasons.append(f"A elevated number of failed login attempts ({val_logins}) strongly pushed this event towards a higher risk rating.")
            elif "Attack_Velocity" in feat or "Velocity" in feat:
                val_vel = df.get("Attack_Velocity", [1])[0]
                reasons.append(f"High traffic frequency ({val_vel} alerts in the last hour) from the source IP indicates automated script scanning.")
            elif "IP_Reputation_Score" in feat or "Reputation" in feat:
                val_rep = df.get("IP_Reputation_Score", [0])[0]
                reasons.append(f"The host IP has a critical historical threat reputation score of {val_rep}/100 based on past blocked exploits.")
            elif "Threat_Density" in feat or "Density" in feat:
                val_den = df.get("Threat_Density", [0.0])[0]
                reasons.append(f"A high density of critical severity alerts ({val_den * 100:.1f}%) within this host's history indicates an active exploit campaign.")
            elif "Anomaly" in feat:
                reasons.append(f"Outlier behavior detected in {feat.replace('_', ' ')} flag indicates an anomalous pattern matching known evasion tactics.")
            else:
                reasons.append(f"Feature '{feat.replace('_', ' ')}' contributed positively to the risk score.")
                
        # Explain negative drivers (which lowered the risk)
        for feat, val in negatives:
            if "Action_Taken" in feat or "Status" in feat:
                reasons.append("The threat has been mitigated or blocked on the firewall sensor, reducing the active risk profile.")
            elif "Session_Duration" in feat and abs(val) > 0.05:
                reasons.append("Brief session duration suggests the connection was dropped or scanning was immediately terminated.")
            else:
                reasons.append(f"Feature '{feat.replace('_', ' ')}' helped lower the threat risk assessment.")

        return reasons

    def _get_fallback_explanations(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Graceful fallback if SHAP initialization fails."""
        # Use simple heuristic rules to explain prediction
        reasons = []
        if df.get("Failed_Login_Count", [0])[0] > 5:
            reasons.append("High failed logins indicates brute force attempts.")
        if df.get("Attack_Velocity", [1])[0] > 10:
            reasons.append("High request velocity indicates automated tool activity.")
        if not reasons:
            reasons.append("The event is classified based on combination of reported severity, network port, and security device sensor profiles.")
            
        return {
            "success": False,
            "feature_impacts": {},
            "top_positive_drivers": [],
            "top_negative_drivers": [],
            "explanations": reasons
        }

    def generate_global_summary_plot(self, X_train_sample: pd.DataFrame, output_path: str = "models/shap_summary.png") -> None:
        """Saves a global SHAP summary bar chart of feature importances across the training sample."""
        if self.explainer is None:
            logger.warning("Cannot generate global summary plot: Explainer is uninitialized.")
            return

        try:
            transformed = self.preprocessor.transform(X_train_sample)
            # Compute shap values on sample
            shap_values = self.explainer(transformed)
            
            plt.figure(figsize=(10, 6))
            # Average shap values across classes for global summary
            if isinstance(shap_values, list):
                shap.summary_plot(shap_values[2], transformed, feature_names=self.feature_names, show=False)
            elif len(shap_values.shape) == 3:
                shap.summary_plot(shap_values.values[:, :, 2], transformed, feature_names=self.feature_names, show=False)
            else:
                shap.summary_plot(shap_values, transformed, feature_names=self.feature_names, show=False)
                
            plt.title("SHAP Global Feature Importance (High Risk Class)", fontsize=14)
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()
            logger.info(f"Saved global SHAP summary plot to: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate global SHAP summary plot: {str(e)}", exc_info=True)
