# A Dual-Approach Intrusion Detection Model: Signature and Heuristic-Based Anomaly Detection in Network Traffic

## Project Overview

This project implements a hybrid intrusion detection system (IDS) that combines two complementary detection approaches:

1. **Signature-Based Detection**: Rule-based detection using known attack patterns and signatures
2. **Heuristic-Based Anomaly Detection**: Machine learning-based detection using statistical anomaly detection

The dual approach leverages the strengths of both methods:
- Signature detection provides high precision for known attacks
- Anomaly detection captures unknown/zero-day attacks and subtle deviations from normal behavior

## Project Structure

```
Dual_IDS_Project/
├── dataset/                    # Network traffic datasets (KDD, NSL-KDD)
│   ├── KDDTrain+.arff
│   ├── KDDTest+.arff
│   └── KDDTest-21.arff
│
├── preprocessing/              # Data processing pipeline
│   ├── __init__.py
│   ├── load_data.py           # Load ARFF format files
│   ├── clean_data.py          # Data cleaning and labeling
│   └── encode_features.py     # Feature encoding and normalization
│
├── signature_module/           # Signature-based detection
│   ├── __init__.py
│   ├── rules.py               # Attack signature rules
│   └── signature_detector.py  # Rule-based detection engine
│
├── anomaly_module/             # Anomaly-based detection
│   ├── __init__.py
│   ├── train_model.py         # ML model training (Random Forest, Isolation Forest)
│   ├── anomaly_detector.py    # ML-based detection engine
│   └── model.pkl              # Trained ML model
│
├── decision_engine/            # Decision fusion engine
│   ├── __init__.py
│   └── decision_logic.py      # Combine signature + anomaly outputs
│
├── evaluation/                 # Model evaluation
│   ├── __init__.py
│   ├── metrics.py             # Performance metrics (accuracy, DR, FPR)
│   └── compare_models.py      # Model comparison and ranking
│
├── logs/                       # Execution logs and alerts
│   └── alerts.log             # Intrusion detection alerts
│
├── utils/                      # Utility functions
│   └── helpers.py             # Common helper functions
│
├── main.py                     # Project entry point
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Setup

1. Clone or download the project:
```bash
cd Dual_IDS_Project
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Module Descriptions

### 1. Preprocessing Module
Handles data loading, cleaning, and feature engineering:
- **load_data.py**: Loads ARFF format KDD dataset files
- **clean_data.py**: Cleans missing values, decodes labels, maps attacks to categories
- **encode_features.py**: Encodes categorical features and normalizes numeric features

### 2. Signature Module
Rule-based intrusion detection:
- **rules.py**: Defines attack signature rules based on known patterns
- **signature_detector.py**: Evaluates traffic against signature rules

### 3. Anomaly Module
Machine learning-based detection:
- **train_model.py**: Trains Random Forest or Isolation Forest models
- **anomaly_detector.py**: Makes predictions on new traffic

### 4. Decision Engine
Combines outputs from both detection methods:
- **decision_logic.py**: Weighted fusion of signature and anomaly scores

### 5. Evaluation Module
Performance measurement and model comparison:
- **metrics.py**: Calculates accuracy, precision, recall, F1, DR, FPR
- **compare_models.py**: Compares and ranks multiple models

## Key Features

### Detection Metrics
- **Accuracy**: Overall correct predictions
- **Detection Rate (DR)**: True positives / (True positives + False negatives)
- **False Positive Rate (FPR)**: False positives / (False positives + True negatives)
- **Precision & Recall**: Trade-off between catching attacks and avoiding false alarms
- **F1-Score**: Harmonic mean of precision and recall

### Attack Categories
- **DoS** (Denial of Service)
- **Probe** (Reconnaissance)
- **R2L** (Remote to Local)
- **U2R** (User to Root)

## Usage

### Basic Workflow

```python
from preprocessing import load_arff_data, clean_data, encode_categorical_features
from signature_module import SignatureDetector
from anomaly_module import AnomalyDetector
from decision_engine import DecisionEngine
from evaluation import calculate_metrics

# 1. Load and preprocess data
train_data = load_arff_data('dataset/KDDTrain+.arff')
train_data = clean_data(train_data)
train_data, encoders, scaler = encode_categorical_features(train_data)

# 2. Train models
# Signature detector (rule-based)
sig_detector = SignatureDetector()

# Anomaly detector (ML-based)
from anomaly_module import train_model
ml_model = train_model(X_train, y_train)
anom_detector = AnomalyDetector(ml_model)

# 3. Decision engine
decision_engine = DecisionEngine(signature_weight=0.4, anomaly_weight=0.6)

# 4. Make predictions
sig_result = sig_detector.detect(test_record)
anom_result = anom_detector.predict(test_record)
final_decision = decision_engine.combine_detections(sig_result, anom_result)

# 5. Evaluate
metrics = calculate_metrics(y_test, predictions)
```

## Configuration

### Tunable Parameters

- **Signature Weight**: Influence of signature detection (0-1)
- **Anomaly Weight**: Influence of ML detection (0-1)
- **Anomaly Threshold**: Classification threshold for anomaly probability
- **Contamination**: Expected proportion of anomalies (for Isolation Forest)

## Performance Goals

- **Detection Rate**: > 95%
- **False Positive Rate**: < 5%
- **Accuracy**: > 98%

## Dependencies

See `requirements.txt` for complete list:
- numpy, pandas: Data processing
- scikit-learn: Machine learning models
- scipy: Scientific computing (ARFF loading)
- matplotlib, seaborn: Visualization

## Logging

All activities are logged to `logs/` directory:
- General execution logs
- Intrusion detection alerts in `alerts.log`

## Future Enhancements

- Integration with live network traffic capture (tcpdump/pcap)
- Deep learning models (LSTM, CNN) for anomaly detection
- Explainability features (SHAP, LIME)
- Real-time alert notifications
- Performance optimization for high-throughput networks
- Support for additional datasets (NSL-KDD, UNSW-NB15)

## References

- KDD Cup 1999 Dataset: http://kdd.ics.uci.edu/databases/kddcup99/
- NSL-KDD: https://www.unb.ca/cic/datasets/nsl-kdd.html

## License

This project is for educational and research purposes.

## Contact & Support

For questions or issues, refer to the project documentation or contact the development team.
