import sys
import os

# Add project root to Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(PROJECT_ROOT)


from flask import Flask, jsonify, render_template
import time
from datetime import datetime, timezone
from sklearn.model_selection import train_test_split

from preprocessing.load_data import load_dataset
from preprocessing.clean_data import clean
from preprocessing.encode_features import fit_transform
from signature_ids.rules import apply_signature_ids
from anomaly_ids.ml_detector import train_random_forest, evaluate_model

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

@app.route("/")
def home():
    return jsonify({
        "status": "Hybrid IDS API is running",
        "available_endpoint": "/analyze"
    })

@app.route("/dashboard")
def dashboard():
    return render_template("index.html")

@app.route("/analyze", methods=["GET"])
def analyze():
    start_time = time.perf_counter()

    try:
        print("STEP 1: Loading dataset")
        t0 = time.perf_counter()
        X, y = load_dataset("KDDTest+.csv")
        dataset_loading_ms = round((time.perf_counter() - t0) * 1000, 3)

        print("STEP 2:", X.shape, y.shape)

        t0 = time.perf_counter()
        cleaned_features, y = clean(X, y)
        cleaning_ms = round((time.perf_counter() - t0) * 1000, 3)
        print("STEP 3: Cleaning complete")

        t0 = time.perf_counter()
        signature_summary = apply_signature_ids(cleaned_features)
        signature_detection_ms = round((time.perf_counter() - t0) * 1000, 3)
        print("STEP 4: Signature IDS complete")

        categorical_cols = ["protocol_type", "service", "flag"]

        t0 = time.perf_counter()
        encoded_features, _ = fit_transform(cleaned_features, categorical_columns=categorical_cols)
        encoding_ms = round((time.perf_counter() - t0) * 1000, 3)
        feature_names = encoded_features.columns.tolist()
        print("STEP 5:", encoded_features.shape)

        X_train, X_test, y_train, y_test = train_test_split(
            encoded_features,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )

        t0 = time.perf_counter()
        random_forest_model = train_random_forest(
            X_train,
            y_train
        )
        model_training_ms = round((time.perf_counter() - t0) * 1000, 3)
        print("STEP 6: Model trained")

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
        model_prediction_ms = round((time.perf_counter() - t0) * 1000, 3)
        print("STEP 7: Prediction complete")

        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

        metadata = {
            "api_version": "2.0",
            "framework": "Flask",
            "dataset": "NSL-KDD",
            "model": "Random Forest",
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        return jsonify({
            "status": "success",
            "metadata": metadata,
            "dataset": {
                "name": "NSL-KDD",
                "samples": int(X.shape[0]),
                "features": int(X.shape[1])
            },
            "signature_detection": signature_summary,
            "ml_detection": ml_summary,
            "performance": {
                "dataset_loading_ms": dataset_loading_ms,
                "cleaning_ms": cleaning_ms,
                "signature_detection_ms": signature_detection_ms,
                "encoding_ms": encoding_ms,
                "model_training_ms": model_training_ms,
                "model_prediction_ms": model_prediction_ms,
                "total_execution_ms": execution_time_ms
            }
        })

    except Exception as e:
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