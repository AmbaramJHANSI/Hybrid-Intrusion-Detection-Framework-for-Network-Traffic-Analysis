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

def apply_signature_ids(X: pd.DataFrame):
    signature_preds = X.apply(detect_attack, axis=1)

    attack_category_map = {
        "smurf": "DoS",
        "neptune": "DoS",
        "portsweep": "Probe",
        "ipsweep": "Probe",
        "satan": "Probe"
    }
    attack_distribution = {}

    for attack in signature_preds:
        if attack == "normal":
            continue

        category = attack_category_map.get(attack, "Other")

        attack_distribution[category] = (
            attack_distribution.get(category, 0) + 1
        )

    total_samples = len(signature_preds)
    attacks_detected = (signature_preds != "normal").sum()
    attack_percentage = round((attacks_detected / total_samples) * 100, 2)

    if attack_percentage < 5:
        risk_level = "LOW"
    elif attack_percentage < 15:
        risk_level = "MEDIUM"
    elif attack_percentage < 30:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    if attack_distribution:
        most_frequent_attack = max(
            attack_distribution,
            key=attack_distribution.get
        )
    else:
        most_frequent_attack = "None"

    signature_summary = {
        "attacks_detected": int(attacks_detected),
        "normal_traffic": int((signature_preds == "normal").sum()),
        "rules_triggered": 5,
        "attack_distribution": attack_distribution,
        "most_frequent_attack": most_frequent_attack,
        "attack_percentage": attack_percentage,
        "risk_level": risk_level
    }

    return signature_summary
