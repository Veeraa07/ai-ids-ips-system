# 🔐 AI-Based Intrusion Detection and Prevention System (IDS/IPS)

A real-time AI-powered IDS/IPS system that monitors network traffic, detects anomalies using machine learning, and prevents malicious activities by automatically blocking suspicious IP addresses.

🔗 GitHub Repository: [https://github.com/Veeraa07/ai-ids-ips-system](https://github.com/Veeraa07/ai-ids-ips-system)

## 📌 Project Overview

This project is designed to improve network security by implementing a smart intrusion detection and prevention system using real-time packet sniffing and AI models. It includes:

- ✅ Real-time packet monitoring with Scapy  
- 🤖 Anomaly detection using Isolation Forest (unsupervised ML)  
- 🔐 Automatic IP blocking for malicious behavior  
- 📊 Live dashboard using Flask  
- 🧾 Anomaly logging and audit-ready logs  

## 🛠️ Features

| Feature           | Description                                        |
|------------------|----------------------------------------------------|
| 🔍 Packet Sniffer | Captures live traffic using Scapy                 |
| 📈 Feature Extractor | Extracts flow-based features from packets     |
| 🧠 ML Detector    | Detects abnormal traffic using Isolation Forest   |
| 🚨 Response Engine | Blocks IP addresses flagged as malicious        |
| 🌐 Flask Dashboard | Displays real-time stats and threat logs         |
| 📂 Log Files      | Saves detected anomalies for review               |

## 📂 Project Structure

ai_ids_ips_project/
├── src/
│ ├── sniff_packets.py
│ ├── feature_extractor.py
│ ├── model_trainer.py
│ ├── intrusion_detector.py
│ ├── response_engine.py
│ └── dashboard.py
├── logs/
│ └── anomaly_log.txt
├── models/
│ └── trained_model.pkl
├── templates/
│ └── dashboard.html
├── requirements.txt
├── README.md


## 🚀 Getting Started

```bash
git clone https://github.com/Veeraa07/ai-ids-ips-system.git
cd ai-ids-ips-system
pip install -r requirements.txt
python src/model_trainer.py
python src/sniff_packets.py
python src/dashboard.py

📊 Dataset
This project uses the CICIDS2017 dataset for training and testing.

🙋‍♂️ Author
Veeraa Suriyaa B
B.E. Cyber Security, Paavai Engineering College
📧 veerasuriya07@gmail.com
🔗 LinkedIn
🔗 GitHub Profile