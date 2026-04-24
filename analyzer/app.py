"""
CBOM Discovery Dashboard
Flask application for visualizing cryptographic inventory
"""
import os
import json
import time
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, jsonify, send_from_directory, request
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

# ---------------------------------------------------------------------------
# Traffic Generator State
# ---------------------------------------------------------------------------
traffic_process = None
traffic_output = []
traffic_lock = threading.Lock()

def run_traffic_scenario(scenario):
    """Run generate-traffic.sh in a subprocess and capture output"""
    global traffic_process, traffic_output
    script_path = "/app/generate-traffic.sh"
    if not os.path.exists(script_path):
        script_path = os.path.join(os.path.dirname(__file__), "..", "generate-traffic.sh")

    with traffic_lock:
        traffic_output = []
        traffic_process = subprocess.Popen(
            ["/bin/bash", script_path, scenario],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

    # Read output in background thread
    def _read_output():
        global traffic_output
        if traffic_process and traffic_process.stdout:
            for line in traffic_process.stdout:
                with traffic_lock:
                    traffic_output.append(line.rstrip())
                    # Keep last 500 lines
                    if len(traffic_output) > 500:
                        traffic_output = traffic_output[-500:]
        with traffic_lock:
            if traffic_process:
                traffic_process.wait()

    threading.Thread(target=_read_output, daemon=True).start()

@app.route("/api/traffic/<scenario>", methods=["POST"])
def api_traffic_run(scenario):
    """Run a traffic scenario: web, ssh, db, mixed, all, loop"""
    global traffic_process
    valid_scenarios = {"web", "ssh", "db", "mixed", "all", "loop"}
    if scenario not in valid_scenarios:
        return jsonify({"status": "error", "message": f"Invalid scenario. Choose from: {', '.join(valid_scenarios)}"}), 400

    with traffic_lock:
        if traffic_process and traffic_process.poll() is None:
            return jsonify({"status": "error", "message": "Traffic generation already running"}), 409

    run_traffic_scenario(scenario)
    return jsonify({"status": "ok", "scenario": scenario, "message": f"Started {scenario} traffic generation"})

@app.route("/api/traffic/status", methods=["GET"])
def api_traffic_status():
    """Get traffic generation status and recent output"""
    with traffic_lock:
        running = traffic_process is not None and traffic_process.poll() is None
        scenario = None
        if traffic_process and isinstance(traffic_process.args, (list, tuple)) and len(traffic_process.args) > 2:
            scenario = traffic_process.args[2]
        return jsonify({
            "status": "ok",
            "running": running,
            "scenario": scenario,
            "output": traffic_output[-100:],  # Last 100 lines
        })

@app.route("/api/traffic/stop", methods=["POST"])
def api_traffic_stop():
    """Stop active traffic generation"""
    global traffic_process
    with traffic_lock:
        if traffic_process and traffic_process.poll() is None:
            traffic_process.terminate()
            try:
                traffic_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                traffic_process.kill()
                traffic_process.wait()
            traffic_process = None
            return jsonify({"status": "ok", "message": "Traffic generation stopped"})
        return jsonify({"status": "ok", "message": "No traffic generation was running"})

@app.route("/api/cbom/clear", methods=["POST"])
def api_cbom_clear():
    """Clear the CBOM by resetting cbom_data and writing an empty CBOM file"""
    global cbom_data, last_update
    try:
        empty_cbom = {
            "metadata": {
                "tool": "CBOM Discovery Tool",
                "version": "1.0.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "format": "CBOM-1.0"
            },
            "summary": {
                "total_crypto_assets": 0,
                "total_services": 0,
                "total_findings": 0,
                "total_certificates": 0,
                "total_keys": 0,
                "risk_score": 0,
                "protocols": {},
                "algorithms": {},
                "key_lengths": {}
            },
            "crypto_assets": [],
            "certificates": [],
            "keys": [],
            "services": [],
            "findings": []
        }
        cbom_data = empty_cbom
        last_update = datetime.utcnow().isoformat() + "Z"

        cbom_file = os.path.join(CBOM_PATH, "cbom.json")
        os.makedirs(CBOM_PATH, exist_ok=True)
        with open(cbom_file, "w") as f:
            json.dump(empty_cbom, f, indent=2)

        return jsonify({"status": "ok", "message": "CBOM cleared successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

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
