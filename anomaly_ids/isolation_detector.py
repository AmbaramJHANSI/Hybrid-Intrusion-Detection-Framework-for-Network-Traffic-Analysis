
"""
isolation_detector.py

Unsupervised anomaly detection for the Hybrid IDS using Isolation Forest.

Output:
    -1: anomaly
     1: normal pattern

Lower decision_function scores indicate more unusual records.
"""

import numpy as np
from sklearn.ensemble import IsolationForest


def train_isolation_forest(X_train, contamination="auto"):
    """
    Train an Isolation Forest on the training features.

    Parameters
    ----------
    X_train:
        Preprocessed and encoded training features.
    contamination:
        "auto" lets scikit-learn determine the decision threshold.
        A float between 0 and 0.5 can be supplied when justified.

    Note
    ----
    This baseline uses all training records without their labels.
    It is unsupervised, but attacks present in the training data can
    influence the patterns learned by the detector.
    """
    if X_train is None or len(X_train) == 0:
        raise ValueError("X_train is empty; cannot train Isolation Forest.")

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train)
    return model


def evaluate_anomalies(model, X_test):
    """
    Detect unusual records and return JSON-serializable results.

    Isolation Forest predict():
        -1 = anomaly
         1 = normal pattern

    decision_function():
        Lower values indicate more unusual records.
        Scores are not attack probabilities.
    """
    if X_test is None or len(X_test) == 0:
        raise ValueError("X_test is empty; cannot detect anomalies.")

    predictions = model.predict(X_test)
    scores = model.decision_function(X_test)

    anomaly_mask = predictions == -1
    anomaly_indices = np.flatnonzero(anomaly_mask)

    flagged_records = [
        {
            "test_record_index": int(index + 1),
            "prediction": "anomaly",
            "anomaly_score": round(float(scores[index]), 6)
        }
        for index in anomaly_indices
    ]

    return {
        "model": "Isolation Forest",
        "samples_analyzed": int(len(predictions)),
        "anomalies_detected": int(np.sum(anomaly_mask)),
        "normal_patterns": int(np.sum(~anomaly_mask)),
        "anomaly_percentage": round(
            float(np.mean(anomaly_mask) * 100), 2
        ),
        "predictions": [
            "anomaly" if prediction == -1 else "normal_pattern"
            for prediction in predictions
        ],
        "anomaly_scores": [
            round(float(score), 6) for score in scores
        ],
        "flagged_records": flagged_records,
        "score_interpretation": (
            "Lower decision_function scores indicate more unusual "
            "records. Scores are not attack probabilities."
        )
    }
