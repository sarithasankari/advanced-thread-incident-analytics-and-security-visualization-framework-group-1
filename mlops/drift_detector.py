"""
MLOps Drift Detection Module
Uses the Population Stability Index (PSI) to detect data distribution drifts
in numerical/categorical features and model prediction outputs.
"""

import os
import sys
from typing import Dict, List, Any, Tuple
import numpy as np
import pandas as pd

# Path configuration
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import settings
from src.utils.logger import get_logger

logger = get_logger("drift_detector")

class DriftDetector:
    """Calculates PSI scores to verify data drift and trigger auto-retraining."""

    def __init__(self, threshold: float = None) -> None:
        self.threshold = threshold or settings.RETRAIN_DRIFT_THRESHOLD

    def calculate_psi(self, expected: pd.Series, actual: pd.Series, num_bins: int = 10) -> float:
        """
        Calculates the Population Stability Index (PSI) between Expected (baseline) 
        and Actual (new target) series.
        
        PSI Formula:
        PSI = Sum( (Actual% - Expected%) * ln(Actual% / Expected%) )
        
        PSI Thresholds:
        - PSI < 0.1: No distribution shift (Stable).
        - 0.1 <= PSI < 0.25: Moderate distribution shift.
        - PSI >= 0.25: Significant distribution shift.
        """
        # Remove nulls
        expected = expected.dropna()
        actual = actual.dropna()

        if len(expected) == 0 or len(actual) == 0:
            return 0.0

        # Handle numeric features via quantile binning
        if pd.api.types.is_numeric_dtype(expected):
            try:
                # Get quantile boundaries on expected
                percentiles = np.linspace(0, 100, num_bins + 1)
                bins = np.percentile(expected, percentiles)
                bins = np.unique(bins) # remove duplicate boundaries
                if len(bins) < 2:
                    # Constant feature fallback
                    bins = np.array([expected.min() - 0.1, expected.max() + 0.1])
            except Exception:
                bins = np.linspace(expected.min() - 0.1, expected.max() + 0.1, num_bins + 1)
            
            # Categorize expected and actual counts into bins
            expected_counts, _ = np.histogram(expected, bins=bins)
            actual_counts, _ = np.histogram(actual, bins=bins)
            
        else:
            # Handle categorical features via unique value frequencies
            all_categories = np.unique(np.concatenate([expected.unique(), actual.unique()]))
            expected_counts = np.array([(expected == cat).sum() for cat in all_categories])
            actual_counts = np.array([(actual == cat).sum() for cat in all_categories])

        # Convert counts to proportions (percentages)
        expected_pcts = expected_counts / len(expected)
        actual_pcts = actual_counts / len(actual)

        # Smooth zero counts to prevent division by zero or log(0) issues
        epsilon = 0.0001
        expected_pcts = np.where(expected_pcts == 0, epsilon, expected_pcts)
        actual_pcts = np.where(actual_pcts == 0, epsilon, actual_pcts)

        # Re-normalize to ensure sums are equal to 1.0 post smoothing
        expected_pcts = expected_pcts / expected_pcts.sum()
        actual_pcts = actual_pcts / actual_pcts.sum()

        # Calculate PSI terms
        psi_value = np.sum((actual_pcts - expected_pcts) * np.log(actual_pcts / expected_pcts))
        return float(psi_value)

    def analyze_dataset_drift(self, reference_df: pd.DataFrame, target_df: pd.DataFrame, 
                              features: List[str]) -> Dict[str, Any]:
        """
        Compares reference (training baseline) and target (newly collected logs) 
        dataframes across numerical and categorical features.
        """
        drift_report = {}
        drift_detected_cols = []
        max_psi = 0.0
        feature_psi_scores = {}

        for col in features:
            if col in reference_df.columns and col in target_df.columns:
                psi = self.calculate_psi(reference_df[col], target_df[col])
                feature_psi_scores[col] = round(psi, 4)
                if psi > max_psi:
                    max_psi = psi
                if psi >= 0.25:
                    drift_detected_cols.append(col)
                    logger.warning(f"🚨 SIGNIFICANT FEATURE DRIFT DETECTED: Column '{col}' PSI score is {psi:.4f}")
                elif psi >= 0.1:
                    logger.info(f"⚠️ Moderate feature drift detected: Column '{col}' PSI score is {psi:.4f}")

        # Compute average feature drift
        mean_psi = float(np.mean(list(feature_psi_scores.values()))) if feature_psi_scores else 0.0
        
        # Suggest retraining if mean feature drift is moderate or any single feature drift is critical
        retrain_suggested = mean_psi >= self.threshold or len(drift_detected_cols) > 0
        
        drift_report = {
            "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mean_psi": round(mean_psi, 4),
            "max_psi": round(max_psi, 4),
            "drift_threshold": self.threshold,
            "drift_detected_features": drift_detected_cols,
            "feature_psi_scores": feature_psi_scores,
            "retrain_suggested": bool(retrain_suggested)
        }
        
        if retrain_suggested:
            logger.warning(f"📢 RETRAINING SUGGESTED: Mean PSI ({mean_psi:.4f}) has crossed threshold limit ({self.threshold})")
            
        return drift_report

if __name__ == "__main__":
    # Test script with dummy series
    detector = DriftDetector()
    s1 = pd.Series(np.random.normal(0, 1, 1000))
    s2 = pd.Series(np.random.normal(0.5, 1.2, 1000)) # shifted distribution
    
    psi_score = detector.calculate_psi(s1, s2)
    print(f"Computed test PSI: {psi_score:.4f}")
