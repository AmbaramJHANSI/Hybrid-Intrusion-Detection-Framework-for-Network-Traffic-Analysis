import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from preprocessing.load_data import load_dataset
from preprocessing.clean_data import clean
from preprocessing.encode_features import fit_transform
from signature_ids.rules import apply_signature_ids
from anomaly_ids.ml_detector import train_random_forest


# -----------------------------
# Page configuration
# -----------------------------
st.set_page_config(
    page_title="Hybrid IDS Dashboard",
    layout="wide"
)

st.title("🔐 Dual-Approach Intrusion Detection System")
st.subheader("Signature-based + Anomaly-based IDS")

# -----------------------------
# Load and preprocess data
# -----------------------------
st.sidebar.header("Dataset Options")

dataset_choice = st.sidebar.selectbox(
    "Select Dataset",
    ["KDDTrain+.csv", "KDDTest+.csv"]
)

X, y = load_dataset(dataset_choice)
X_clean, y = clean(X, y)

# -----------------------------
# Dataset overview
# -----------------------------
st.header("📊 Dataset Overview")

col1, col2, col3 = st.columns(3)
col1.metric("Total Records", X_clean.shape[0])
col2.metric("Total Features", X_clean.shape[1])
col3.metric("Attack Ratio", f"{(y == 'attack').mean():.2%}")

st.write("Label Distribution")
st.bar_chart(y.value_counts())

# -----------------------------
# Signature-based IDS
# -----------------------------
st.header("🛡️ Signature-based IDS")

signature_preds = apply_signature_ids(X_clean)
st.write("Signature Detection Results")
st.bar_chart(signature_preds.value_counts())

# -----------------------------
# Anomaly-based IDS (Random Forest)
# -----------------------------
st.header("🤖 Anomaly-based IDS (ML)")

categorical_cols = ["protocol_type", "service", "flag"]
X_enc, _ = fit_transform(X_clean, categorical_columns=categorical_cols)

model = train_random_forest(X_enc, y)
ml_preds = model.predict(X_enc)

st.write("Anomaly Detection Results")
st.bar_chart(pd.Series(ml_preds).value_counts())

# -----------------------------
# Confusion Matrix
# -----------------------------
st.header("📈 Confusion Matrix (ML Model)")

from sklearn.metrics import confusion_matrix

cm = confusion_matrix(y, ml_preds, labels=["attack", "normal"])

fig, ax = plt.subplots()
sns.heatmap(cm, annot=True, fmt="d",
            xticklabels=["Attack", "Normal"],
            yticklabels=["Attack", "Normal"],
            ax=ax)

ax.set_xlabel("Predicted")
ax.set_ylabel("Actual")

st.pyplot(fig)

# -----------------------------
# Final message
# -----------------------------
st.success("IDS Pipeline Executed Successfully 🚀")
