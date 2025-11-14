"""
url_inspector.py
----------------
Performs phishing URL inspection using heuristics and (optional) ML model.
"""

import re
import math
import joblib
from urllib.parse import urlparse

# Try loading pre-trained ML model (optional)
try:
    clf = joblib.load("models/url_clf.joblib")
    MODEL_AVAILABLE = True
except:
    MODEL_AVAILABLE = False
print("✅ ML Model Loaded:", MODEL_AVAILABLE)


# Some known suspicious top-level domains
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work"}

def hostname_entropy(host: str) -> float:
    """Calculate character entropy of hostname."""
    if not host:
        return 0
    probs = {}
    for ch in host:
        probs[ch] = probs.get(ch, 0) + 1
    total = len(host)
    entropy = -sum((v / total) * math.log2(v / total) for v in probs.values())
    return entropy


def extract_features(url: str):
    """Extract basic numerical & boolean features from the URL."""
    p = urlparse(url)
    features = {}
    features["length"] = len(url)
    features["host_len"] = len(p.netloc)
    features["num_dots"] = p.netloc.count(".")
    features["num_slashes"] = url.count("/")
    features["has_ip"] = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", p.netloc))
    features["contains_at"] = "@" in url
    features["contains_percent"] = "%" in url
    features["entropy"] = hostname_entropy(p.netloc)
    features["suspicious_tld"] = any(p.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS)
    features["has_https"] = url.lower().startswith("https")
    return features


def heuristic_score(features: dict) -> (float, str):
    """
    Quick rule-based evaluation.
    Returns (risk_score, reason)
    """
    score = 0
    reasons = []

    if features["has_ip"]:
        score += 0.5
        reasons.append("IP address used in hostname")

    if features["contains_at"]:
        score += 0.4
        reasons.append("Contains '@' symbol (redirect trick)")

    if features["contains_percent"]:
        score += 0.3
        reasons.append("Encoded characters (%) in URL")

    if features["suspicious_tld"]:
        score += 0.3
        reasons.append("Suspicious TLD (.tk/.ml/etc)")

    if features["length"] > 200:
        score += 0.2
        reasons.append("Unusually long URL")

    if features["num_slashes"] > 10:
        score += 0.2
        reasons.append("Too many subdirectories")

    if features["entropy"] > 4.2:
        score += 0.3
        reasons.append("High domain entropy (random hostname)")

    # Cap score between 0 and 1
    score = min(1.0, score)

    # Default reason if clean
    if not reasons:
        reasons.append("Heuristics indicate safe URL")

    return score, "; ".join(reasons)


def inspect_url(url: str):
    """
    Main inspection function.
    Returns (risk_score, reason)
    """
    features = extract_features(url)

    # First: rule-based heuristics
    heuristic_risk, heuristic_reason = heuristic_score(features)

    # If high risk by heuristics, no need for ML
    if heuristic_risk >= 0.7 or not MODEL_AVAILABLE:
        return heuristic_risk, heuristic_reason

    # Otherwise: use ML model for fine-tuning
    feature_vector = [
        [
            features["length"],
            features["host_len"],
            features["num_dots"],
            features["num_slashes"],
            features["entropy"],
            int(features["contains_at"]),
            int(features["contains_percent"]),
            int(features["suspicious_tld"]),
        ]
    ]

    prob = clf.predict_proba(feature_vector)[0][1]
    combined_score = max(prob, heuristic_risk)

    return combined_score, f"ML+Heuristic score (ML={prob:.2f}, heuristics={heuristic_risk:.2f})"
