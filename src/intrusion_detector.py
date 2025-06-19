import joblib
import numpy as np
from src.feature_extractor import extract_features

# Load the trained model
model = joblib.load('models/anomaly_detector.pkl')

# Function to check if a packet is an intrusion
def check_intrusion(packet):
    try:
        features = extract_features(packet)
        values = np.array(list(features.values())).reshape(1, -1)
        prediction = model.predict(values)
        return prediction[0] == -1  # -1 means anomaly
    except Exception as e:
        print(f"Error during detection: {e}")
        return False
from src.response_engine import block_ip

def detect_anomaly(packet, model):
    features = extract_features(packet)
    prediction = model.predict(features)[0]

    if prediction == -1:
        ip = packet[0][1].src if hasattr(packet[0][1], "src") else "Unknown"
        print(f"🚨 Anomaly Detected from IP: {ip}")
        block_ip(ip)
