"""clean_data.py

Decoding, cleaning and labeling helpers for ARFF-loaded datasets.

Functions here operate on the DataFrame `X` and Series `y` returned by `load_data`.
"""
from typing import Tuple
import pandas as pd
import numpy as np


def _fill_numeric(series: pd.Series) -> pd.Series:
    if series.isnull().any():
        return series.fillna(series.median())
    return series


def _fill_categorical(series: pd.Series) -> pd.Series:
    if series.isnull().any():
        mode = series.mode()
        fill = mode.iloc[0] if not mode.empty else ""
        return series.fillna(fill)
    return series


def clean(X: pd.DataFrame, y: pd.Series = None) -> Tuple[pd.DataFrame, pd.Series]:
    """Return cleaned (X_clean, y_clean).

    Cleaning steps:
    - Trim whitespace for object dtypes
    - Convert numeric-like strings to numeric dtype where possible
    - Fill missing numeric values with median and categorical with mode
    - Normalize labels to two classes: 'normal' and 'attack' (if `y` provided)
    """
    X = X.copy()

    for col in X.columns:
        if X[col].dtype == object:
            X[col] = X[col].astype(str).str.strip()
            # try to convert to numeric if values look numeric
            coerced = pd.to_numeric(X[col], errors="coerce")
            if not coerced.isnull().all():
                X[col] = _fill_numeric(coerced)
            else:
                X[col] = _fill_categorical(X[col])
        else:
            # numeric column
            X[col] = _fill_numeric(X[col])

    if y is None:
        return X, None

    y = y.copy().astype(str).str.strip()
    # Map label values: if label equals 'normal' (case-insensitive) keep 'normal', else 'attack'
    def map_label(v: str) -> str:
        return "normal" if v.lower() == "normal" else "attack"

    y = y.apply(map_label)

    return X, y

