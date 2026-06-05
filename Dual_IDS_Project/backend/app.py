import sys
import os

# Add project root to Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(PROJECT_ROOT)

from flask import Flask, jsonify
import pandas as pd

from preprocessing.load_data import load_dataset
from preprocessing.clean_data import clean
from preprocessing.encode_features import fit_transform
from signature_ids.rules import apply_signature_ids
from anomaly_ids.ml_detector import train_random_forest

app = Flask(__name__)

@app.route("/analyze", methods=["GET"])
def analyze():
    # Load data
    X, y = load_dataset("KDDTest+.csv")
    X_clean, y = clean(X, y)

    # Signature-based IDS
    signature_preds = apply_signature_ids(X_clean)

    # Anomaly-based IDS
    categorical_cols = ["protocol_type", "service", "flag"]
    X_enc, _ = fit_transform(X_clean, categorical_columns=categorical_cols)
    model = train_random_forest(X_enc, y)
    anomaly_preds = model.predict(X_enc)

    response = {
        "total_records": len(y),
        "signature_results": signature_preds.value_counts().to_dict(),
        "anomaly_results": pd.Series(anomaly_preds).value_counts().to_dict()
    }

    return jsonify(response)

if __name__ == "__main__":
    app.run(debug=True)
