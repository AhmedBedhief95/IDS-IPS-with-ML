import scapy.all as scapy
import pandas as pd
import joblib
import requests
import time
from datetime import datetime

# --- CONFIGURATION ---
MODEL_PATH = 'ips_model.pkl'
BACKEND_URL = "http://127.0.0.1:5000/update"
INTERFACE = "eth0"  # Change to "wlan0" or your specific interface

# --- LOAD ML MODEL ---
try:
    model = joblib.load(MODEL_PATH)
    print(f"[*] ML Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    print(f"[!] Error loading model: {e}")
    exit()

def get_protocol_name(proto_num):
    """Maps protocol numbers to human-readable strings."""
    mapping = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    return mapping.get(proto_num, 'OTHER')

def packet_callback(packet):
    """Processed every intercepted packet."""
    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto_num = packet[scapy.IP].proto
            pkt_size = len(packet)
            
            # Prepare data for ML model
            # Features must match the order used during training (e.g., proto, size)
            features = pd.DataFrame([[proto_num, pkt_size]], columns=['protocol', 'size'])
            
            # Perform Inference
            prediction = model.predict(features)[0]
            
            # Map prediction to Severity and Action
            # Assuming 0=Info, 1=Low, 2=Medium, 3=High
            severity_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High"}
            severity = severity_map.get(prediction, "Low")
            action = "BLOCKED" if severity == "High" else "ALLOWED"

            # Construct JSON Payload
            packet_data = {
                "src": src_ip,
                "dst": dst_ip,
                "proto": get_protocol_name(proto_num),
                "size": pkt_size,
                "severity": severity,
                "action": action
            }

            # Send to Flask Backend
            try:
                requests.post(BACKEND_URL, json=packet_data, timeout=0.5)
            except requests.exceptions.RequestException:
                pass # Silently fail if backend is temporarily unreachable

    except Exception as e:
        print(f"[!] Error processing packet: {e}")

# --- START SNIFFING ---
if __name__ == "__main__":
    print(f"[*] Starting Sniffer on {INTERFACE}...")
    print(f"[*] Reporting to {BACKEND_URL}")
    
    # Use store=0 to prevent memory leaks during long runs
    scapy.sniff(iface=INTERFACE, prn=packet_callback, store=0)
