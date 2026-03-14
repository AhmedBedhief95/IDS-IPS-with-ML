from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION ---
RECORDS_DIR = 'records'
RECORDS_FILE = os.path.join(RECORDS_DIR, 'records.json')
packet_log = [] # Temporary buffer for the live dashboard

# --- STORAGE INITIALIZATION ---
def initialize_storage():
    """Ensures the records directory and file exist with correct permissions."""
    try:
        if not os.path.exists(RECORDS_DIR):
            os.makedirs(RECORDS_DIR)
            print(f"[*] Created directory: {RECORDS_DIR}")

        if not os.path.exists(RECORDS_FILE) or os.stat(RECORDS_FILE).st_size == 0:
            with open(RECORDS_FILE, 'w') as f:
                json.dump([], f)
            print(f"[*] Initialized new {RECORDS_FILE}")
        
        # Ensure the file is readable/writable by the sniffer (sudo) and the app
        os.chmod(RECORDS_FILE, 0o666)
    except Exception as e:
        print(f"[!] Storage Initialization Error: {e}")

def save_blocked_record(data):
    """Appends a high-severity threat to the persistent JSON file."""
    try:
        with open(RECORDS_FILE, 'r+') as f:
            records = json.load(f)
            records.append(data)
            f.seek(0)
            json.dump(records, f, indent=4)
            f.truncate()
    except Exception as e:
        print(f"[!] Error saving to records.json: {e}")

# --- API ENDPOINTS ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/update', methods=['POST'])
def update():
    """Endpoint for sniffer.py to report detected packets."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    # Add server-side timestamp
    data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Update live log (limit to 50 items for performance)
    packet_log.insert(0, data)
    if len(packet_log) > 50:
        packet_log.pop()

    # 2. Persistent storage for High Severity threats
    if data.get('severity') == 'High':
        save_blocked_record(data)
        print(f"[ALERT] High Severity packet recorded from {data.get('src')}")

    return jsonify({"status": "success"})

@app.route('/data', methods=['GET'])
def get_data():
    """Endpoint for the dashboard to fetch live updates."""
    # Calculate simple stats for the charts
    stats = {
        "TCP": len([p for p in packet_log if p.get('proto') == 'TCP']),
        "UDP": len([p for p in packet_log if p.get('proto') == 'UDP']),
        "ICMP": len([p for p in packet_log if p.get('proto') == 'ICMP']),
        "High": len([p for p in packet_log if p.get('severity') == 'High'])
    }
    return jsonify({"packets": packet_log, "stats": stats})

@app.route('/get_history', methods=['GET'])
def get_history():
    """Endpoint for the history page to fetch stored alerts."""
    try:
        with open(RECORDS_FILE, 'r') as f:
            records = json.load(f)
        return jsonify(records)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    initialize_storage()
    print("\n--- Starting IPS Server ---")
    print(f"[*] Dashboard available at http://127.0.0.1:5000")
    # Set debug=True for development, False for production
    app.run(debug=True, port=5000)
