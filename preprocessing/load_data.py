"""
load_data.py
Utilities to load NSL-KDD CSV datasets from the local dataset/ folder.
"""
from typing import Tuple, List
import os
import pandas as pd

# Project root
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_DIR = os.path.join(ROOT, "dataset")

def available_datasets() -> List[str]:
    """Return list of available CSV dataset filenames."""
    if not os.path.isdir(DATASET_DIR):
        return []
    return [f for f in os.listdir(DATASET_DIR) if f.lower().endswith(".csv")]

def load_csv(path: str) -> Tuple[pd.DataFrame, pd.Series]:
    """Load CSV dataset and return (X, y)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"CSV file not found: {path}")

    df = pd.read_csv(path)

    # Drop rows with a missing target label; they are incomplete examples and
    # should not participate in model training/evaluation.
    df = df.dropna(subset=["class"]).reset_index(drop=True)

    # Last column is label
    y = df.iloc[:, -1].astype(str).copy()
    X = df.iloc[:, :-1].copy()

    return X, y

def load_dataset(filename: str) -> Tuple[pd.DataFrame, pd.Series]:
    """Load dataset by filename from dataset/ folder."""
    if os.path.basename(filename) != filename:
        raise ValueError("Provide only filename, not full path")

    if filename not in available_datasets():
        raise FileNotFoundError(f"{filename} not found in dataset/")

    path = os.path.join(DATASET_DIR, filename)
    return load_csv(path)
