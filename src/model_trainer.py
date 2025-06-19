import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load dataset (make sure this file exists in the data/ folder)
df = pd.read_csv('data/CICIDS2017.csv')  # Replace with your dataset filename

# Select numeric columns and clean data
features = df.select_dtypes(include=['float64', 'int64']).dropna()

# Train the Isolation Forest model
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(features)

# Save the trained model
joblib.dump(model, 'models/anomaly_detector.pkl')
print("✅ Model trained and saved at models/anomaly_detector.pkl")
