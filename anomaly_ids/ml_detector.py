"""
ml_detector.py

Anomaly-based IDS using machine learning models.
"""

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

CLASS_LABELS = ("normal", "attack")
CLASS_NAMES = ("Normal Traffic", "Attack Traffic")


def train_logistic_regression(X_train, y_train):
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    return model


def train_random_forest(X_train, y_train):
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )
    model.fit(X_train, y_train)
    return model


def evaluate_model(
    model,
    X_test,
    y_test,
    feature_names=None,
    model_name="Model",
    training_samples=None,
    testing_samples=None
):
    preds = model.predict(X_test)

    top_features = []

    if hasattr(model, "feature_importances_") and feature_names is not None:
        feature_scores = list(zip(feature_names, model.feature_importances_))
        feature_scores.sort(key=lambda x: x[1], reverse=True)
        top_features = [
            {
                "feature": feature,
                "importance": float(score),
                "importance_percent": float(score) * 100
            }
            for feature, score in feature_scores[:10]
        ]

    unexpected_labels = (set(y_test) | set(preds)) - set(CLASS_LABELS)
    if unexpected_labels:
        raise ValueError(
            "Expected normalized class labels 'normal' and 'attack'; "
            f"received unexpected labels: {sorted(unexpected_labels)}"
        )

    cm = confusion_matrix(y_test, preds, labels=CLASS_LABELS)
    tn, fp, fn, tp = cm.ravel()
    report = classification_report(
        y_test,
        preds,
        labels=CLASS_LABELS,
        target_names=CLASS_NAMES,
        output_dict=True,
        zero_division=0
    )

    print(f"\n=== {model_name} Evaluation ===")
    print("Accuracy:", accuracy_score(y_test, preds))
    print("\nClassification Report:")
    print(classification_report(
        y_test,
        preds,
        labels=CLASS_LABELS,
        target_names=CLASS_NAMES,
        zero_division=0
    ))

    return {
        "model": model_name,
        "accuracy": float(accuracy_score(y_test, preds)),
        "precision": float(precision_score(y_test, preds, average="weighted", zero_division=0)),
        "recall": float(recall_score(y_test, preds, average="weighted", zero_division=0)),
        "f1_score": float(f1_score(y_test, preds, average="weighted", zero_division=0)),
        "attack_precision": float(report["Attack Traffic"]["precision"]),
        "attack_recall": float(report["Attack Traffic"]["recall"]),
        "attack_f1_score": float(report["Attack Traffic"]["f1-score"]),

        "training_samples": training_samples,
        "testing_samples": testing_samples,
        "top_features": top_features,
        "class_order": list(CLASS_NAMES),

        "confusion_matrix": {
            "labels": list(CLASS_NAMES),
            "matrix": cm.tolist(),
            "true_positive": int(tp),
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn)
        },
        "classification_report": report
    }