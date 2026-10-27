
"""
app.py

Flask API for the Hybrid Intrusion Detection System.

Components:
1. Signature-based detection
2. Supervised Random Forest classification
3. Unsupervised Isolation Forest anomaly detection
"""

import os
import sys
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
import numpy as np

# Add project root to Python path
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing.load_data import load_dataset
from preprocessing.clean_data import clean
from preprocessing.encode_features import fit_transform

from signature_ids.rules import apply_signature_ids
from anomaly_ids.ml_detector import (
    train_random_forest,
    evaluate_model
)
from anomaly_ids.isolation_detector import (
    train_isolation_forest,
    evaluate_anomalies
)


app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)


def evaluate_isolation_forest(y_test, anomaly_predictions):
    """Evaluate anomaly flags against normalized ground-truth labels.

    clean() maps the original NSL-KDD label "normal" to "normal" and every
    other label to "attack". For evaluation only, anomaly is treated as the
    predicted attack class and normal_pattern as predicted normal.
    """
    y_true_labels = np.asarray(y_test).reshape(-1)
    predictions = np.asarray(anomaly_predictions).reshape(-1)

    if len(y_true_labels) != len(predictions):
        raise ValueError(
            "Ground-truth labels and Isolation Forest predictions "
            "must contain the same number of records."
        )

    y_true_labels = np.char.lower(
        np.char.strip(y_true_labels.astype(str))
    )
    actual_classes = set(np.unique(y_true_labels))
    if not actual_classes.issubset({"normal", "attack"}):
        raise ValueError(
            "Expected normalized ground-truth labels: "
            "'normal' or 'attack'."
        )

    predicted_classes = set(np.unique(predictions))
    if not predicted_classes.issubset({"anomaly", "normal_pattern"}):
        raise ValueError(
            "Expected Isolation Forest predictions: "
            "'anomaly' or 'normal_pattern'."
        )

    y_true_binary = (y_true_labels == "attack").astype(int)
    y_pred_binary = (predictions == "anomaly").astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_true_binary,
        y_pred_binary,
        labels=[0, 1]
    ).ravel()

    return {
        "samples_evaluated": int(len(y_true_binary)),
        "true_positive": int(tp),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "accuracy": float(accuracy_score(y_true_binary, y_pred_binary)),
        "precision": float(precision_score(
            y_true_binary, y_pred_binary, zero_division=0
        )),
        "recall": float(recall_score(
            y_true_binary, y_pred_binary, zero_division=0
        )),
        "f1_score": float(f1_score(
            y_true_binary, y_pred_binary, zero_division=0
        )),
        "classification_report": classification_report(
            y_true_binary,
            y_pred_binary,
            labels=[0, 1],
            target_names=["Normal Traffic", "Attack Traffic"],
            output_dict=True,
            zero_division=0
        )
    }


@app.after_request
def disable_analysis_response_caching(response):
    if request.path == "/analyze":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def home():
    return jsonify({
        "status": "Hybrid IDS API is running",
        "available_endpoints": [
            "/",
            "/dashboard",
            "/analyze"
        ],
        "detection_components": [
            "Signature-based detection",
            "Random Forest classification",
            "Isolation Forest anomaly detection"
        ]
    })


@app.route("/dashboard")
def dashboard():
    return render_template("index.html")


@app.route("/analyze", methods=["GET"])
def analyze():
    start_time = time.perf_counter()

    try:
        # --------------------------------------------------
        # STEP 1: Load dataset
        # --------------------------------------------------
        print("STEP 1: Loading dataset")

        t0 = time.perf_counter()
        X, y = load_dataset("KDDTest+.csv")
        dataset_loading_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )

        print("Dataset shape:", X.shape)
        print("Label shape:", y.shape)

        # --------------------------------------------------
        # STEP 2: Clean data
        # --------------------------------------------------
        print("STEP 2: Cleaning dataset")

        t0 = time.perf_counter()
        cleaned_features, y = clean(X, y)
        cleaning_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )

        # --------------------------------------------------
        # STEP 3: Signature-based detection
        # --------------------------------------------------
        print("STEP 3: Running signature-based detection")

        t0 = time.perf_counter()
        signature_summary = apply_signature_ids(cleaned_features)
        signature_detection_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )

        # --------------------------------------------------
        # STEP 4: Encode features
        # --------------------------------------------------
        print("STEP 4: Encoding features")

        categorical_cols = [
            "protocol_type",
            "service",
            "flag"
        ]

        t0 = time.perf_counter()
        encoded_features, _ = fit_transform(
            cleaned_features,
            categorical_columns=categorical_cols
        )
        encoding_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )

        feature_names = encoded_features.columns.tolist()

        print("Encoded feature shape:", encoded_features.shape)

        # --------------------------------------------------
        # STEP 5: Split data
        # --------------------------------------------------
        print("STEP 5: Splitting training and testing data")

        X_train, X_test, y_train, y_test = train_test_split(
            encoded_features,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )

        print("Training samples:", len(X_train))
        print("Testing samples:", len(X_test))

        # --------------------------------------------------
        # STEP 6: Train and evaluate Random Forest
        # --------------------------------------------------
        print("STEP 6: Training Random Forest")

        t0 = time.perf_counter()
        random_forest_model = train_random_forest(
            X_train,
            y_train
        )
        model_training_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )

        print("STEP 7: Evaluating Random Forest")

        t0 = time.perf_counter()
        ml_summary = evaluate_model(
            random_forest_model,
            X_test,
            y_test,
            feature_names=feature_names,
            model_name="Random Forest",
            training_samples=len(X_train),
            testing_samples=len(X_test)
        )
        model_prediction_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )

        # --------------------------------------------------
        # STEP 8: Train Isolation Forest
        # --------------------------------------------------
        print("STEP 8: Training Isolation Forest")

        t0 = time.perf_counter()
        isolation_forest_model = train_isolation_forest(
            X_train,
            contamination="auto"
        )
        anomaly_training_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )

        # --------------------------------------------------
        # STEP 9: Detect anomalies
        # --------------------------------------------------
        print("STEP 9: Detecting anomalies")

        t0 = time.perf_counter()
        anomaly_summary = evaluate_anomalies(
            isolation_forest_model,
            X_test
        )
        anomaly_prediction_ms = round(
            (time.perf_counter() - t0) * 1000, 3
        )
        isolation_evaluation = evaluate_isolation_forest(
            y_test,
            anomaly_summary["predictions"]
        )

        print(
            "Anomalies flagged:",
            anomaly_summary["anomalies_detected"]
        )

        # --------------------------------------------------
        # STEP 10: Prepare response metadata
        # --------------------------------------------------
        execution_time_ms = round(
            (time.perf_counter() - start_time) * 1000, 3
        )

        metadata = {
            "api_version": "3.0",
            "framework": "Flask",
            "dataset": "NSL-KDD",
            "classification_model": "Random Forest",
            "anomaly_model": "Isolation Forest",
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        # --------------------------------------------------
        # STEP 11: Return results
        # --------------------------------------------------
        return jsonify({
            "status": "success",
            "metadata": metadata,

            "dataset": {
                "name": "NSL-KDD",
                "samples": int(X.shape[0]),
                "features": int(X.shape[1]),
                "training_samples": int(len(X_train)),
                "testing_samples": int(len(X_test))
            },

            # Existing signature-based detector
            "signature_detection": signature_summary,

            # Existing supervised Random Forest classifier
            "ml_detection": ml_summary,

            # New unsupervised Isolation Forest detector
            "anomaly_detection": {
                **anomaly_summary,
                "evaluation": isolation_evaluation
            },

            "performance": {
                "dataset_loading_ms": dataset_loading_ms,
                "cleaning_ms": cleaning_ms,
                "encoding_ms": encoding_ms,
                "signature_detection_ms": signature_detection_ms,
                "model_training_ms": model_training_ms,
                "model_prediction_ms": model_prediction_ms,
                "anomaly_training_ms": anomaly_training_ms,
                "anomaly_prediction_ms": anomaly_prediction_ms,
                "total_execution_ms": execution_time_ms
            }
        })

    except Exception as e:
        app.logger.exception("IDS analysis failed")

        return jsonify({
            "status": "error",
            "message": str(e),
            "type": type(e).__name__
        }), 500


if __name__ == "__main__":
    app.run(
        debug=True,
        use_reloader=False
    )
