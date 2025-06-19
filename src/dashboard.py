from flask import Flask, render_template_string, jsonify
import threading
from scapy.all import sniff
import pandas as pd
import joblib
import platform
import subprocess

app = Flask(__name__)
model = joblib.load('models/anomaly_detector.pkl')

# State
stats = {
    "total": 0,
    "anomalies": 0
}

# HTML Template with Chart.js
html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>AI IDS/IPS Dashboard</title>
    <meta http-equiv="refresh" content="10">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial; background: #f4f4f4; padding: 30px; }
        .box { background: white; padding: 20px; border-radius: 10px; width: 600px; box-shadow: 0 0 10px rgba(0,0,0,0.2); }
        .title { font-size: 24px; font-weight: bold; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="box">
        <div class="title">🛡️ AI IDS/IPS Dashboard</div>
        <canvas id="trafficChart" width="400" height="250"></canvas>
    </div>
    <script>
        async function fetchStats() {
            const res = await fetch("/stats");
            const data = await res.json();
            const chartData = {
                labels: ['Normal', 'Anomalies'],
                datasets: [{
                    data: [data.total - data.anomalies, data.anomalies],
                    backgroundColor: ['green', 'red']
                }]
            };
            new Chart(document.getElementById('trafficChart'), {
                type: 'doughnut',
                data: chartData
            });
        }
        fetchStats();
    </script>
</body>
</html>
"""

def extract_features(packet):
    return pd.DataFrame([{
        'packet_len': len(packet),
        'src_port': getattr(packet, 'sport', 0),
        'dst_port': getattr(packet, 'dport', 0),
        'protocol': getattr(packet, 'proto', 0),
    }])

def block_ip(ip):
    os_type = platform.system()
    print(f"🔒 Blocking IP: {ip}")
    if os_type == "Windows":
        subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in interface=any action=block remoteip={ip}', shell=True)
    elif os_type == "Linux":
        subprocess.run(f'sudo iptables -A INPUT -s {ip} -j DROP', shell=True)

def detect(packet):
    stats["total"] += 1
    features = extract_features(packet)
    prediction = model.predict(features)[0]
    if prediction == -1:
        stats["anomalies"] += 1
        src_ip = packet[0][1].src if hasattr(packet[0][1], "src") else "Unknown"
        print(f"🚨 Anomaly from {src_ip}")
        block_ip(src_ip)

def start_sniffer():
    sniff(prn=detect, store=0)

@app.route('/')
def dashboard():
    return render_template_string(html_template)

@app.route('/stats')
def get_stats():
    return jsonify(stats)

if __name__ == '__main__':
    thread = threading.Thread(target=start_sniffer, daemon=True)
    thread.start()
    app.run(host="0.0.0.0", port=5000)
