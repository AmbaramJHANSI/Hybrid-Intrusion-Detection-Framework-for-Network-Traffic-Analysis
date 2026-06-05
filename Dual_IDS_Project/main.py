"""
main.py

Entry point for the Dual-Approach Intrusion Detection System.
Pipeline:
CSV → Cleaning → Signature IDS → Encoding → (later) Anomaly IDS
"""
from anomaly_ids.ml_detector import (
    train_logistic_regression,
    train_random_forest,
    evaluate_model
)

from preprocessing.load_data import load_dataset
from preprocessing.clean_data import clean
from preprocessing.encode_features import fit_transform, transform, ENCODERS_DIR
from signature_ids.rules import apply_signature_ids


def run_pipeline():
    print("=== Starting Dual-Approach IDS Pipeline ===")

    # -------------------------------------------------
    # 1. Load CSV datasets
    # -------------------------------------------------
    print("\n[1] Loading datasets...")
    X_train, y_train = load_dataset("KDDTrain+.csv")
    X_test, y_test = load_dataset("KDDTest+.csv")

    print("Train shape:", X_train.shape)
    print("Test shape :", X_test.shape)

    # -------------------------------------------------
    # 2. Clean data
    # -------------------------------------------------
    print("\n[2] Cleaning datasets...")
    X_train_clean, y_train = clean(X_train, y_train)
    X_test_clean, y_test = clean(X_test, y_test)

    print("\nLabel distribution (train):")
    print(y_train.value_counts())

    # -------------------------------------------------
    # 3. Signature-based IDS (RULE-BASED)
    # -------------------------------------------------
    print("\n[3] Signature-based IDS detection...")
    signature_preds = apply_signature_ids(X_train_clean)

    print("\nSignature detection results:")
    print(signature_preds.value_counts())

    # -------------------------------------------------
    # 4. Encode categorical features (for ML later)
    # -------------------------------------------------
    print("\n[4] Encoding categorical features...")
    categorical_cols = ["protocol_type", "service", "flag"]

    X_train_enc, encoders = fit_transform(
        X_train_clean,
        categorical_columns=categorical_cols,
        save_path=ENCODERS_DIR
    )

    X_test_enc = transform(X_test_clean, encoders)

    # -------------------------------------------------
    # 5. Final verification
    # -------------------------------------------------
    print("\n[5] Verification")
    print("Encoded train shape:", X_train_enc.shape)
    print("Encoded test shape :", X_test_enc.shape)

    print("\nSample encoded rows:")
    print(X_train_enc.head())

    print("\nData types summary:")
    print(X_train_enc.dtypes.value_counts())

    print("\n=== Pipeline completed successfully ===")

    # -------------------------------------------------
    # 6. Anomaly-based IDS (ML)
    # -------------------------------------------------
    print("\n[6] Anomaly-based IDS (Machine Learning)")

    # Train models
    lr_model = train_logistic_regression(X_train_enc, y_train)
    rf_model = train_random_forest(X_train_enc, y_train)

    # Evaluate models
    lr_preds = evaluate_model(
        lr_model, X_test_enc, y_test, "Logistic Regression"
    )

    rf_preds = evaluate_model(
        rf_model, X_test_enc, y_test, "Random Forest"
    ) 


if __name__ == "__main__":
   run_pipeline()
