"""
proxy.py
---------
Main Zero-Trust Firewall proxy with phishing URL inspection,
policy enforcement, and a web dashboard interface.
"""

from flask import Flask, request, Response, jsonify, render_template_string
import requests, os, json
from app.url_inspector import inspect_url
from app.policy_engine import enforce_policy
from app.logger import log_decision
from app.config import ALLOW_THRESHOLD

app = Flask(__name__)

# -------------------- BASIC ROUTES --------------------

@app.route("/")
def home():
    return jsonify({
        "message": "Zero-Trust Firewall with Phishing URL Inspection",
        "usage": "Visit /dashboard to use the web UI"
    })


@app.route("/fetch")
def fetch_url():
    """Core endpoint used internally by the dashboard (proxy behavior)."""
    user = request.headers.get("X-User", "anonymous")
    device = request.headers.get("X-Device-Posture", "unknown")
    url = request.args.get("url")

    if not url:
        return jsonify({"error": "Missing URL parameter"}), 400

    # --- Inspection ---
    risk_score, reason = inspect_url(url)

    # --- Policy Enforcement ---
    decision, policy_reason = enforce_policy(user, device, risk_score)

    # --- Logging ---
    log_decision(user, url, risk_score, decision, reason, policy_reason)

    if decision == "BLOCK":
        html = f"""
        <html>
        <head><title>Access Blocked</title></head>
        <body style="font-family:sans-serif;background:#f8d7da;color:#721c24;padding:20px;">
            <h1>🚫 Access Blocked</h1>
            <p><b>URL:</b> {url}</p>
            <p><b>Risk Score:</b> {risk_score:.2f}</p>
            <p><b>Reason:</b> {reason}</p>
            <p><b>Policy:</b> {policy_reason}</p>
            <a href="/dashboard">⬅ Back to Dashboard</a>
        </body>
        </html>
        """
        return Response(html, status=403, mimetype="text/html")

    # Allow request (proxy behavior)
    try:
        resp = requests.get(url, stream=True, timeout=10)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]
        return Response(resp.raw, status=resp.status_code, headers=headers)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------- DASHBOARD --------------------

@app.route("/dashboard")
def dashboard():
    """Display all logged decisions in a table with search & filter."""
    log_file = "logs/decisions.log"
    entries = []

    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except:
                    continue

    html = """
    <html>
    <head>
        <title>Zero-Trust Firewall Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f9f9f9; margin: 40px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #333; color: #fff; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .BLOCK { background-color: #f8d7da; color: #721c24; }
            .ALLOW { background-color: #d4edda; color: #155724; }
            .REVIEW { background-color: #fff3cd; color: #856404; }
            h1 { color: #333; }
            a { text-decoration: none; color: #007bff; }
            .form-box { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            input[type=text] { padding: 6px; border: 1px solid #ccc; border-radius: 5px; }
            button { padding: 8px 15px; border: none; background-color: #007bff; color: white; border-radius: 5px; cursor: pointer; }
            button:hover { background-color: #0056b3; }
            .search-bar { margin-top: 10px; }
        </style>
        <script>
            function filterTable() {
                let query = document.getElementById('search').value.toLowerCase();
                let rows = document.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    let text = row.innerText.toLowerCase();
                    row.style.display = text.includes(query) ? '' : 'none';
                });
            }
        </script>
    </head>
    <body>
        <h1>🛡️ Zero-Trust Firewall Dashboard</h1>
        <div class="form-box">
            <form action="/inspect" method="get">
                <input type="text" name="url" placeholder="Enter URL to inspect" size="60" required>
                <input type="text" name="user" placeholder="User name (e.g., aniket)">
                <input type="text" name="device" placeholder="Device (trusted/unverified)">
                <button type="submit">Inspect URL</button>
            </form>
        </div>

        <div class="search-bar">
            <input type="text" id="search" onkeyup="filterTable()" placeholder="Search logs...">
        </div>

        <h2>Recent Logs</h2>
        <table>
            <thead>
            <tr>
                <th>Time</th>
                <th>User</th>
                <th>URL</th>
                <th>Risk</th>
                <th>Decision</th>
                <th>Reason</th>
                <th>Policy</th>
            </tr>
            </thead>
            <tbody>
            {% for log in entries[::-1][:100] %}
            <tr class="{{ log.decision }}">
                <td>{{ log.timestamp }}</td>
                <td>{{ log.user }}</td>
                <td><a href="{{ log.url }}" target="_blank">{{ log.url }}</a></td>
                <td>{{ log.risk_score }}</td>
                <td>{{ log.decision }}</td>
                <td>{{ log.inspection_reason }}</td>
                <td>{{ log.policy_reason }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </body>
    </html>
    """
    return render_template_string(html, entries=entries)


@app.route("/inspect")
def inspect():
    """Handle user form submission from dashboard."""
    url = request.args.get("url")
    user = request.args.get("user", "anonymous")
    device = request.args.get("device", "unknown")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    risk_score, reason = inspect_url(url)
    decision, policy_reason = enforce_policy(user, device, risk_score)
    log_decision(user, url, risk_score, decision, reason, policy_reason)

    color = "#d4edda" if decision == "ALLOW" else "#f8d7da" if decision == "BLOCK" else "#fff3cd"

    return f"""
    <html><body style="font-family:sans-serif; background:{color}; padding:20px;">
        <h1>Firewall Decision: {decision}</h1>
        <p><b>User:</b> {user}</p>
        <p><b>Device:</b> {device}</p>
        <p><b>URL:</b> {url}</p>
        <p><b>Risk Score:</b> {risk_score:.2f}</p>
        <p><b>Inspection Reason:</b> {reason}</p>
        <p><b>Policy Reason:</b> {policy_reason}</p>
        <a href="/dashboard">⬅ Back to Dashboard</a>
    </body></html>
    """


# -------------------- RUN APP --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
