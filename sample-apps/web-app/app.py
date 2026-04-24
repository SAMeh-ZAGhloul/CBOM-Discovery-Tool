"""
Sample HTTPS Web Application
Demonstrates TLS 1.2/1.3 with various cipher suites
"""
from flask import Flask, jsonify, render_template_string
from OpenSSL import SSL
import os

app = Flask(__name__)

# HTML page with crypto info
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>CBOM Demo - Secure Web App</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .secure { color: green; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🔐 CBOM Discovery Demo</h1>
    <div class="card">
        <h2>Secure Web Application</h2>
        <p>This application uses <span class="secure">TLS encryption</span> for secure communication.</p>
        <ul>
            <li>Protocol: <code>HTTPS/TLS 1.2+</code></li>
            <li>Certificate: <code>RSA 2048-bit</code></li>
            <li>Cipher: <code>AES-256-GCM</code></li>
            <li>Key Exchange: <code>ECDHE</code></li>
        </ul>
    </div>
    <div class="card">
        <h3>API Endpoints</h3>
        <ul>
            <li><code>GET /api/data</code> - Returns encrypted data payload</li>
            <li><code>GET /api/health</code> - Health check</li>
        </ul>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

@app.route("/api/data")
def api_data():
    return jsonify({
        "status": "secure",
        "encryption": "TLS 1.2+",
        "algorithm": "AES-256-GCM",
        "key_exchange": "ECDHE",
        "message": "This data is transmitted over an encrypted channel"
    })

@app.route("/api/health")
def health():
    return jsonify({"status": "healthy", "service": "web-app"})

if __name__ == "__main__":
    context = ('/app/certs/cert.pem', '/app/certs/key.pem')
    app.run(host='0.0.0.0', port=8443, ssl_context=context, threaded=True)
