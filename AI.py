from datetime import datetime
from pymongo import MongoClient
import os
import json
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]
alerts_collection = mongo_db["alerts"]

anomaly_detector = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
scaler = StandardScaler()

def read_logs(file_path):
    if not os.path.exists(file_path):
        print(f"Error: Log file {file_path} does not exist")
        return []
    try:
        with open(file_path, "r") as file:
            logs = file.readlines()
            print(f"Read {len(logs)} logs from file {file_path}")
            return logs
    except Exception as e:
        print(f"Error reading log file {file_path}: {e}")
        return []

def extract_features(logs):
    features = []
    for log in logs:
        log_length = len(log)
        error_count = log.lower().count("error")
        failed_count = log.lower().count("failed")
        suspicious_keywords = log.lower().count("unauthorized") + log.lower().count("malicious")
        special_chars_count = sum(not c.isalnum() for c in log)
        uppercase_ratio = sum(1 for c in log if c.isupper()) / log_length

        features.append([log_length, error_count, failed_count, suspicious_keywords, special_chars_count, uppercase_ratio])
    return np.array(features)

def train_anomaly_detector(normal_logs, malicious_logs=[]):
    normal_features = extract_features(normal_logs)
    if len(malicious_logs) > 0:
        malicious_features = extract_features(malicious_logs)
        features = np.vstack((normal_features, malicious_features))
    else:
        features = normal_features
    
    if features.size == 0:
        print("No features extracted for anomaly detector training.")
        return

    features = scaler.fit_transform(features)
    anomaly_detector.fit(features)
    print("Anomaly detector trained on combined logs.")

def detect_anomalies(logs):
    """Detect anomalies in logs using the trained anomaly detector."""
    features = extract_features(logs)
    if features.size == 0:
        print("No features to predict for anomaly detection.")
        return []

    features = scaler.transform(features)
    predictions = anomaly_detector.predict(features)
    anomalies = [log for log, pred in zip(logs, predictions) if pred == -1]
    return anomalies

def update_malicious_logs_in_mongodb(logs):
    """Update malicious logs in MongoDB."""
    try:
        for log in logs:
            log_entry = {
                "message": log.strip(),
                "@timestamp": datetime.now().isoformat(),
            }
            malicious_logs_collection.update_one(
                {"message": log_entry["message"]}, {"$set": log_entry}, upsert=True
            )
        print(f"Updated {len(logs)} malicious logs in MongoDB")
    except Exception as e:
        print(f"Error updating malicious logs in MongoDB: {e}")

def generate_alert(matched_logs):
    try:
        for log in matched_logs:
            alert_entry = {
                "message": log,
                "severity": "High",
                "category": "Malicious Log Detected",
                "timestamp": datetime.now().isoformat(),
                "description": "A log entry matched known malicious patterns or was detected as anomalous",
            }
            alerts_collection.insert_one(alert_entry)
        print(f"Generated {len(matched_logs)} alerts for malicious logs.")
    except Exception as e:
        print(f"Error generating alerts: {e}")

def train_on_new_logs(log_path):
    new_logs = read_logs(log_path)
    if new_logs:
        historical_malicious_logs = [entry['message'] for entry in malicious_logs_collection.find()]
        train_anomaly_detector(new_logs, historical_malicious_logs)

if __name__ == "__main__":
    log_directory = "Log_Analysis/Collected_Logs"
    os.makedirs(log_directory, exist_ok=True)

    client_logs_path = "D:\elasticsearch\malicious_logs\malicious_logs.log"

    print("Training anomaly detector...")
    normal_logs = ["Successful login", "File accessed", "User logged out"]
    train_anomaly_detector(normal_logs)

    train_on_new_logs(client_logs_path)

    client_logs = read_logs(client_logs_path)
    
    if client_logs:
        anomalies = detect_anomalies(client_logs)
        if anomalies:
            print(f"Anomalous logs detected!")
            generate_alert(anomalies)
            update_malicious_logs_in_mongodb(anomalies)
        else:
            print("No anomalies detected in logs.")
    else:
        print("No client logs to analyze for anomalies.")
