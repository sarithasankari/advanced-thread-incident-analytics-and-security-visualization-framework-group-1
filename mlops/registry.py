"""
MLOps Model Registry Module
Manages model versioning, archiving, and promoting champion classifiers.
"""

import os
import sys
import shutil
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

# Path configuration
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import settings
from src.utils.logger import get_logger

logger = get_logger("model_registry")

class ModelRegistry:
    """Manages model versioning, archiving, and champion promotions."""

    def __init__(self, registry_dir: str = None) -> None:
        self.registry_dir = registry_dir or settings.MODEL_REGISTRY_DIR
        os.makedirs(self.registry_dir, exist_ok=True)

    def register_model(self, version: str, metrics: Dict[str, Any], feature_names: List[str]) -> str:
        """
        Copies the current best model to the registry with a version name.
        Saves a metadata manifest file.
        """
        model_src = settings.MODEL_PATH
        if not os.path.exists(model_src):
            raise FileNotFoundError(f"Source model file not found at: {model_src}. Train the model first.")

        # Paths in registry
        model_dest = os.path.join(self.registry_dir, f"model_v_{version}.joblib")
        meta_dest = os.path.join(self.registry_dir, f"model_v_{version}_meta.json")

        # Copy model pipeline
        shutil.copy(model_src, model_dest)

        # Build manifest
        manifest = {
            "version": version,
            "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "feature_names": feature_names,
            "metrics": metrics,
            "model_file": model_dest
        }

        with open(meta_dest, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)

        logger.info(f"Model version '{version}' successfully archived in registry.")
        return model_dest

    def list_models(self) -> List[Dict[str, Any]]:
        """Scans the registry directory and returns list of metadata manifests."""
        models = []
        for file in os.listdir(self.registry_dir):
            if file.endswith("_meta.json"):
                meta_path = os.path.join(self.registry_dir, file)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        models.append(meta)
                except Exception as e:
                    logger.error(f"Failed to read model metadata {file}: {str(e)}")
        
        # Sort by registration date descending
        models.sort(key=lambda x: x.get("registered_at", ""), reverse=True)
        return models

    def promote_to_champion(self, version: str) -> None:
        """Promotes a registered version to the active champion model."""
        model_src = os.path.join(self.registry_dir, f"model_v_{version}.joblib")
        meta_src = os.path.join(self.registry_dir, f"model_v_{version}_meta.json")

        if not os.path.exists(model_src) or not os.path.exists(meta_src):
            raise FileNotFoundError(f"Model version '{version}' does not exist in registry.")

        # Copy back to main paths
        shutil.copy(model_src, settings.MODEL_PATH)
        
        # Load and update metrics summary
        with open(meta_src, "r", encoding="utf-8") as f:
            meta = json.load(f)
            
        summary_metrics = {
            "best_model_name": f"Registry Version {version}",
            "risk_mapping": {"Low Risk": 0, "Medium Risk": 1, "High Risk": 2},
            "inverse_risk_mapping": {"0": "Low Risk", "1": "Medium Risk", "2": "High Risk"},
            "feature_names": meta.get("feature_names", []),
            "metrics": {f"Version {version}": meta.get("metrics", {})}
        }
        
        with open(settings.METRICS_PATH, "w", encoding="utf-8") as f:
            json.dump(summary_metrics, f, indent=4)

        logger.info(f"Model version '{version}' successfully promoted to champion.")

if __name__ == "__main__":
    # Test registry class
    reg = ModelRegistry()
    print("Registered Models:")
    print(reg.list_models())
