"""encode_features.py

Categorical encoding utilities using per-column LabelEncoders.

Functions:
- `fit_encoders(X, categorical_columns=None, save_path=None)` : fits LabelEncoders for categorical columns and optionally saves them with joblib
- `transform(X, encoders)` : transforms DataFrame using fitted encoders
- `fit_transform(X, save_path=None)` : convenience that fits and transforms and saves encoders
- `load_encoders(path)` : load saved encoders
"""
from typing import Dict, List, Optional, Tuple
import os

import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENCODERS_DIR = os.path.join(ROOT, "preprocessing", "encoders")
os.makedirs(ENCODERS_DIR, exist_ok=True)


def _get_categorical_columns(X: pd.DataFrame) -> List[str]:
    return [c for c in X.columns if X[c].dtype == object or X[c].dtype.name == "category"]


def fit_encoders(X: pd.DataFrame, categorical_columns: Optional[List[str]] = None, save_path: Optional[str] = None) -> Dict[str, LabelEncoder]:
    """Fit LabelEncoders for categorical columns in X.

    Returns a dict mapping column name -> fitted LabelEncoder.
    If `save_path` is provided, encoders are saved via joblib to that path (directory).
    """
    X = X.copy()
    cols = categorical_columns or _get_categorical_columns(X)

    encoders: Dict[str, LabelEncoder] = {}
    for col in cols:
        le = LabelEncoder()
        # convert to str to ensure consistent handling of mixed types
        values = X[col].astype(str).fillna("").values
        le.fit(values)
        encoders[col] = le

    if save_path:
        os.makedirs(save_path, exist_ok=True)
        for col, le in encoders.items():
            joblib.dump(le, os.path.join(save_path, f"{col}.joblib"))

    return encoders


def transform(X: pd.DataFrame, encoders: Dict[str, LabelEncoder]) -> pd.DataFrame:
    """Return a transformed copy of X where categorical columns are label-encoded.

    Columns without encoders are left unchanged.
    """
    X = X.copy()
    for col, le in encoders.items():
        if col in X.columns:
            X[col] = X[col].astype(str).fillna("")
            # handle unseen labels by mapping to -1
            X[col] = X[col].map(lambda x: le.transform([x])[0] if x in le.classes_ else -1)
    return X


def fit_transform(X: pd.DataFrame, categorical_columns: Optional[List[str]] = None, save_path: Optional[str] = None) -> Tuple[pd.DataFrame, Dict[str, LabelEncoder]]:
    """Fit encoders, transform X and optionally save encoders to `save_path`."""
    encoders = fit_encoders(X, categorical_columns=categorical_columns, save_path=save_path)
    Xt = transform(X, encoders)
    return Xt, encoders


def load_encoders(path: str) -> Dict[str, LabelEncoder]:
    """Load all encoder joblib files in `path` and return dict col->encoder."""
    encoders: Dict[str, LabelEncoder] = {}
    if not os.path.isdir(path):
        return encoders
    for filename in os.listdir(path):
        if filename.endswith(".joblib"):
            col = filename[:-7]
            encoders[col] = joblib.load(os.path.join(path, filename))
    return encoders

