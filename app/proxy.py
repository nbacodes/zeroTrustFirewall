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
        <head>
            <title>Access Blocked</title>
            <style>
                body {{
                    font-family: Arial;
                    background: #2a0000;
                    color: #ffcccc;
                    padding: 40px;
                }}
                .card {{
                    background: #3a0000;
                    padding: 25px;
                    border-radius: 12px;
                    box-shadow: 0 0 10px rgba(255,0,0,0.3);
                }}
                a {{ color: #ff6666; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🚫 Access Blocked</h1>
                <p><b>URL:</b> {url}</p>
                <p><b>Risk Score:</b> {risk_score:.2f}</p>
                <p><b>Reason:</b> {reason}</p>
                <p><b>Policy:</b> {policy_reason}</p>
                <a href="/dashboard">⬅ Back to Dashboard</a>
            </div>
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
    """Display all logged decisions with improved UI."""
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
            body {
                margin: 0;
                background: #0d1117;
                color: #e6edf3;
                font-family: 'Segoe UI', sans-serif;
            }
            header {
                background: linear-gradient(90deg,#0d6efd,#6610f2);
                padding: 25px;
                text-align: center;
                color: white;
                font-size: 28px;
                font-weight: bold;
                box-shadow: 0 2px 8px rgba(0,0,0,0.4);
            }
            .container {
                padding: 30px;
                max-width: 1200px;
                margin: auto;
            }
            .card {
                background: #161b22;
                padding: 20px;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.4);
                margin-bottom: 25px;
            }
            input[type=text] {
                padding: 10px;
                width: 250px;
                border-radius: 8px;
                border: 1px solid #30363d;
                background: #0d1117;
                color: white;
                margin-right: 10px;
            }
            button {
                padding: 10px 18px;
                border: none;
                border-radius: 8px;
                background: #0d6efd;
                color: white;
                cursor: pointer;
            }
            button:hover { background: #0b5ed7; }

            table {
                width: 100%;
                margin-top: 20px;
                border-collapse: collapse;
                font-size: 14px;
            }
            th {
                background: #21262d;
                color: #e6edf3;
                padding: 12px;
            }
            td {
                padding: 10px;
                border-bottom: 1px solid #30363d;
            }
            tr:hover { background: #161b22; }

            .badge {
                padding: 5px 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            .ALLOW { background: #1a7f37; color: white; }
            .BLOCK { background: #da3633; color: white; }
            .REVIEW { background: #e3b341; color: black; }

            a { color: #58a6ff; text-decoration: none; }
        </style>

        <script>
            function filterTable() {
                let query = document.getElementById('search').value.toLowerCase();
                let rows = document.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    row.style.display = row.innerText.toLowerCase().includes(query) ? '' : 'none';
                });
            }
        </script>
    </head>

    <body>
        <header>🛡 Zero-Trust Firewall Dashboard</header>

        <div class="container">

            <div class="card">
                <h2>🔍 Inspect a URL</h2>
                <form action="/inspect" method="get">
                    <input type="text" name="url" placeholder="Enter URL to inspect" required>
                    <input type="text" name="user" placeholder="User (e.g., aniket)">
                    <input type="text" name="device" placeholder="Device (trusted/unverified)">
                    <button type="submit">Analyze URL</button>
                </form>
            </div>

            <div class="card">
                <h2>📜 Recent Logs</h2>
                <input type="text" id="search" onkeyup="filterTable()" placeholder="Search logs...">

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
                        {% for log in entries[::-1][:200] %}
                        <tr>
                            <td>{{ log.timestamp }}</td>
                            <td>{{ log.user }}</td>
                            <td><a href="{{ log.url }}" target="_blank">{{ log.url }}</a></td>
                            <td>{{ log.risk_score }}</td>
                            <td><span class="badge {{ log.decision }}">{{ log.decision }}</span></td>
                            <td>{{ log.inspection_reason }}</td>
                            <td>{{ log.policy_reason }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

        </div>
    </body>
    </html>
    """
    return render_template_string(html, entries=entries)


# -------------------- INSPECT PAGE --------------------

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

    color = "#1a7f37" if decision == "ALLOW" else "#da3633" if decision == "BLOCK" else "#e3b341"

    return f"""
    <html>
    <body style="font-family:Segoe UI, sans-serif; background:#0d1117; color:#e6edf3; padding:40px;">
        <div style="max-width:800px;margin:auto;background:#161b22;padding:25px;border-radius:12px;
                    box-shadow:0 4px 12px rgba(0,0,0,0.4);">

            <h1 style="color:{color};">Firewall Decision: {decision}</h1>

            <p><b>User:</b> {user}</p>
            <p><b>Device:</b> {device}</p>
            <p><b>URL:</b> <a href="{url}" target="_blank" style="color:#58a6ff;">{url}</a></p>

            <p><b>Risk Score:</b> {risk_score:.2f}</p>
            <p><b>Inspection Reason:</b> {reason}</p>
            <p><b>Policy Reason:</b> {policy_reason}</p>

            <br>
            <a href="/dashboard" style="color:#58a6ff;">⬅ Back to Dashboard</a>
        </div>
    </body>
    </html>
    """


# -------------------- RUN APP --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
