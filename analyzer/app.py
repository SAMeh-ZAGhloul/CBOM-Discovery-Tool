"""
CBOM Discovery Dashboard
Flask application for visualizing cryptographic inventory
"""
import os
import json
import time
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, send_from_directory
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cbom_generator import CBOMGenerator

app = Flask(__name__)

# Configuration
LOG_PATH = os.environ.get("LOG_PATH", "/app/logs")
CBOM_PATH = os.environ.get("CBOM_PATH", "/app/cbom")
PORT = int(os.environ.get("FLASK_PORT", "5000"))

cbom_data = None
cbom_generator = CBOMGenerator(LOG_PATH, CBOM_PATH)
last_update = None

class LogHandler(FileSystemEventHandler):
    """Watch for new Zeek logs and regenerate CBOM"""
    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('.log'):
            time.sleep(1)  # Wait for write to complete
            regenerate_cbom()

    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('.log'):
            time.sleep(1)
            regenerate_cbom()

def regenerate_cbom():
    """Regenerate CBOM from current logs"""
    global cbom_data, last_update, cbom_generator
    try:
        cbom_generator = CBOMGenerator(LOG_PATH, CBOM_PATH)
        cbom_data = cbom_generator.generate()
        last_update = datetime.utcnow().isoformat() + "Z"
        print(f"[CBOM] Regenerated at {last_update}")
    except Exception as e:
        print(f"[CBOM] Error regenerating: {e}")

def start_watcher():
    """Start file system watcher for logs"""
    if not os.path.exists(LOG_PATH):
        os.makedirs(LOG_PATH)

    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, LOG_PATH, recursive=True)
    observer.start()

    # Initial generation
    regenerate_cbom()

    try:
        while True:
            time.sleep(60)
            # Periodic refresh
            regenerate_cbom()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

@app.route("/")
def dashboard():
    """Main dashboard"""
    return render_template("index.html")

@app.route("/api/cbom")
def api_cbom():
    """Get full CBOM data"""
    if cbom_data is None:
        regenerate_cbom()
    return jsonify(cbom_data or {})

@app.route("/api/summary")
def api_summary():
    """Get summary only"""
    if cbom_data is None:
        regenerate_cbom()
    return jsonify(cbom_data.get("summary", {}) if cbom_data else {})

@app.route("/api/findings")
def api_findings():
    """Get findings only"""
    if cbom_data is None:
        regenerate_cbom()
    return jsonify(cbom_data.get("findings", []) if cbom_data else [])

@app.route("/api/assets")
def api_assets():
    """Get crypto assets"""
    if cbom_data is None:
        regenerate_cbom()
    return jsonify(cbom_data.get("crypto_assets", []) if cbom_data else [])

@app.route("/api/certificates")
def api_certificates():
    """Get certificates"""
    if cbom_data is None:
        regenerate_cbom()
    return jsonify(cbom_data.get("certificates", []) if cbom_data else [])

@app.route("/api/services")
def api_services():
    """Get services"""
    if cbom_data is None:
        regenerate_cbom()
    return jsonify(cbom_data.get("services", []) if cbom_data else [])

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Force CBOM regeneration"""
    regenerate_cbom()
    return jsonify({"status": "ok", "last_update": last_update})

@app.route("/download/cbom")
def download_cbom():
    """Download CBOM JSON file"""
    return send_from_directory(CBOM_PATH, "cbom.json", as_attachment=True)

@app.template_filter('datetime')
def format_datetime(value):
    """Format ISO datetime for display"""
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return value

if __name__ == "__main__":
    # Start log watcher in background thread
    watcher_thread = threading.Thread(target=start_watcher, daemon=True)
    watcher_thread.start()

    app.run(host="0.0.0.0", port=PORT, debug=True)
