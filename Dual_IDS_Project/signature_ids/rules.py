"""
rules.py

Signature-based intrusion detection rules
"""

import pandas as pd


def detect_attack(row):
    # SMURF
    if row["protocol_type"] == "icmp" and row["dst_bytes"] == 0 and row["count"] > 100:
        return "smurf"

    # NEPTUNE
    if row["protocol_type"] == "tcp" and row["service"] == "private" and row["serror_rate"] > 0.5:
        return "neptune"

    # PORTSWEEP
    if row["srv_diff_host_rate"] > 0.5 and row["count"] > 50:
        return "portsweep"

    # IPSWEEP
    if row["diff_srv_rate"] > 0.5 and row["dst_host_count"] > 100:
        return "ipsweep"

    # SATAN
    if row["num_failed_logins"] > 3 and row["logged_in"] == 0:
        return "satan"

    return "normal"


def apply_signature_ids(X: pd.DataFrame) -> pd.Series:
    return X.apply(detect_attack, axis=1)
