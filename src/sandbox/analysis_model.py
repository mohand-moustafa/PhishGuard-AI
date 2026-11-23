"""Offline inference using the project's fitted PCA, LR baseline and XGBoost residual."""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MODELS = Path(__file__).resolve().parents[2] / "models"


@lru_cache(maxsize=1)
def _load_models() -> tuple:
    import joblib
    import xgboost as xgb

    # Fixed deployment-owned paths only. Neither the worker nor the API supplies model files.
    metadata = json.loads((MODELS / "xgboost/xgboost_info.json").read_text())
    pipeline = joblib.load(MODELS / "full_pca_pipeline.joblib")
    baseline = joblib.load(MODELS / "xgboost/lr_model.joblib")
    booster = xgb.Booster(params={"nthread": 1})
    booster.load_model(MODELS / "xgboost/lr_xgb_booster.json")
    return pipeline, baseline, booster, metadata


def predict_url(url: str) -> dict[str, Any]:
    """Return the probability and additive contributions on the training model's logit scale."""
    unavailable = {"status": "unavailable", "model": "Logistic Regression + XGBoost",
                   "probability": None, "shap": None}
    try:
        if not url or len(url) > 8192 or ":" in (urlsplit(url).hostname or ""):
            return {**unavailable, "reason": "URL outside the training extractor's supported host format"}
        import numpy as np
        import pandas as pd
        import xgboost as xgb
        from .analysis_features import model_features

        pipeline, baseline, booster, metadata = _load_models()
        row = model_features(url)
        names = list(pipeline.feature_names_in_)
        values = pipeline.transform(pd.DataFrame([[row[name] for name in names]], columns=names))
        components = metadata["features"]
        margin = baseline.decision_function(values)
        matrix = xgb.DMatrix(values, base_margin=margin, nthread=1)
        probability = float(booster.predict(matrix)[0])
        contributions = booster.predict(matrix, pred_contribs=True)[0]
        # The booster's bias includes this row's LR margin. Move its feature-dependent
        # part into the PC contributions, explaining LR relative to the PCA origin.
        linear = (baseline.coef_[0] * values[0]).astype(float)
        attribution = contributions[:-1] + linear
        bias = float(contributions[-1] - np.sum(linear))
        if not np.all(np.isfinite(attribution)) or not np.isfinite(bias + probability):
            raise ValueError("non-finite model output")
        return {
            "status": "available", "model": "Logistic Regression + XGBoost",
            "probability": probability, "threshold": metadata["threshold"],
            "label": "phishing" if probability > metadata["threshold"] else "legitimate",
            "missing_inputs": ["domain_age"],
            "feature_note": "Unknown registration age follows the training notebook's missing-age comparison.",
            "shap": {"method": "XGBoost TreeSHAP plus linear PCA contributions", "unit": "log_odds",
                     "base_value": bias, "values": dict(zip(components, map(float, attribution)))},
        }
    except (ImportError, OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError) as error:
        return {**unavailable, "reason": f"Model artifact or runtime unavailable ({type(error).__name__})"}
