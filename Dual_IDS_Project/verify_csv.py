import pandas as pd
import os
import sys


MIN_REQUIRED_ROWS = 100  # representative subset threshold
EXPECTED_COLUMNS = 42


def verify_csv(path):
    print("\n======================================")
    print(f"Verifying file: {os.path.basename(path)}")

    if not os.path.exists(path):
        raise FileNotFoundError(f" File not found: {path}")

    df = pd.read_csv(path)

    rows, cols = df.shape
    print(f"Shape (rows, columns): ({rows}, {cols})")

    # ---- Critical checks ----
    if rows == 0:
        raise ValueError(" CSV has ZERO rows — invalid dataset")

    if cols != EXPECTED_COLUMNS:
        raise ValueError(f" Expected {EXPECTED_COLUMNS} columns, got {cols}")

    # ---- Dataset size warning ----
    if rows < MIN_REQUIRED_ROWS:
        print(f" WARNING: Dataset is small ({rows} rows). Using as representative subset.")

    # ---- Label column ----
    if "class" in df.columns:
        label_col = "class"
    elif "label" in df.columns:
        label_col = "label"
    else:
        raise ValueError(" No label column found")

    print("Label column:", label_col)

    label_counts = df[label_col].value_counts()
    print("\nLabel distribution:")
    print(label_counts)

    if label_counts.empty:
        raise ValueError(" Label column is empty")

    # ---- Missing values ----
    missing = df.isnull().sum().sum()
    if missing != 0:
        print(f"⚠️ WARNING: Missing values found: {missing}")
    else:
        print("No missing values found")

    

    print("\nSample rows:")
    print(df.head(3))

    print(" Verification SUCCESS")


if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATASET_DIR = os.path.join(BASE_DIR, "dataset")

    try:
        verify_csv(os.path.join(DATASET_DIR, "KDDTrain+.csv"))
        verify_csv(os.path.join(DATASET_DIR, "KDDTest+.csv"))
        verify_csv(os.path.join(DATASET_DIR, "KDDTest-21.csv"))
    except Exception as e:
        print("\nVERIFICATION FAILED ")
        print(e)
        sys.exit(1)
