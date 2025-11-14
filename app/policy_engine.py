"""
policy_engine.py
----------------
Implements Zero-Trust rules combining user, device, and risk factors
to decide whether to ALLOW, BLOCK, or REVIEW the request.
"""

from app.config import ALLOW_THRESHOLD

def enforce_policy(user: str, device: str, risk_score: float):
    """
    Evaluate the request against Zero-Trust policies.
    Returns: (decision, reason)
    """

    # --- 1️⃣ Authentication Check ---
    if user.lower() == "anonymous":
        return "BLOCK", "Unauthenticated user — Zero-Trust requires identity verification"

    # --- 2️⃣ Device Posture Check ---
    if device.lower() not in ["trusted", "compliant"]:
        if risk_score > 0.3:
            return "BLOCK", "Unverified device and elevated risk"
        else:
            return "REVIEW", "Device not compliant; review required"

    # --- 3️⃣ Risk-based Decision ---
    if risk_score >= 0.85:
        return "BLOCK", "High phishing probability detected"
    elif risk_score >= ALLOW_THRESHOLD:
        return "REVIEW", f"Medium risk ({risk_score:.2f}) — manual review needed"
    else:
        return "ALLOW", f"Risk low ({risk_score:.2f}) — access permitted"

