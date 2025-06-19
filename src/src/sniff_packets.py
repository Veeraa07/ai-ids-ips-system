import joblib
import pandas as pd
from scapy.all import sniff
from sklearn.ensemble import IsolationForest
from datetime import datetime
import os

# Load the trained model
model = joblib.load('models/anomaly_detector.pkl')

# Make sure log folder exists
os.makedirs("logs", exist_ok=True)

# Log function
def log_anomaly(packet):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_port = packet.sport if hasattr(packet, 'sport') else "N/A"
    dst_port = packet.dport if hasattr(packet, 'dport') else "N/A"
    proto = packet.proto if hasattr(packet, 'proto') else "N/A"
    log_entry = f"[{now}] 🔴 Anomaly Detected | Src Port: {src_port}, Dst Port: {dst_port}, Protocol: {proto}\n"

    with open("logs/anomaly_log.txt", "a") as log_file:
        log_file.write(log_entry)

# Feature extraction
def extract_features(packet):
    try:
        features = {
            'packet_len': len(packet),
            'src_port': packet.sport if hasattr(packet, 'sport') else 0,
            'dst_port': packet.dport if hasattr(packet, 'dport') else 0,
            'protocol': packet.proto if hasattr(packet, 'proto') else 0,
        }
        return pd.DataFrame([features])
    except Exception as e:
        print("⚠️ Packet skipped due to error:", e)
        return None

# Detection logic
def detect(packet):
    features = extract_features(packet)
    if features is not None:
        prediction = model.predict(features)[0]
        if prediction == -1:
            print("🔴 Anomaly Detected!")
            log_anomaly(packet)
        else:
            print("🟢 Normal Traffic")

# Run the sniffer for 60 seconds
print("🚀 Starting packet sniffing for 60 seconds...")
sniff(prn=detect, store=0, timeout=60)
print("🛑 Sniffing stopped. Check logs/anomaly_log.txt for results.")
