from datetime import datetime
from pymongo import MongoClient
import os
from sklearn.ensemble import IsolationForest
import numpy as np

# MongoDB connection
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]
alerts_collection = mongo_db["alerts"]

# Initialize Isolation Forest for anomaly detection
anomaly_detector = IsolationForest(contamination=0.01, random_state=42)

def read_logs(file_path):
    """Reads logs from a file."""
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
    """Extract features from logs for anomaly detection."""
    features = []
    for log in logs:
        log_length = len(log)
        error_count = log.lower().count("error")
        failed_count = log.lower().count("failed")
        features.append([log_length, error_count, failed_count])
    return np.array(features)

def train_anomaly_detector(normal_logs):
    """Train the anomaly detector on normal logs."""
    features = extract_features(normal_logs)
    if features.size == 0:
        print("No features extracted for anomaly detector training.")
        return

    anomaly_detector.fit(features)
    print("Anomaly detector trained on normal logs.")

def detect_anomalies(logs):
    """Detect anomalies in logs using the trained anomaly detector."""
    features = extract_features(logs)
    if features.size == 0:
        print("No features to predict for anomaly detection.")
        return []

    predictions = anomaly_detector.predict(features)
    anomalies = [log for log, pred in zip(logs, predictions) if pred == -1]
    return anomalies

def get_malicious_logs_from_mongodb():
    """Fetch existing malicious logs from MongoDB."""
    try:
        return list(malicious_logs_collection.find({}, {"_id": 0, "message": 1}))
    except Exception as e:
        print(f"Error fetching malicious logs from MongoDB: {e}")
        return []

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
    """Generate alerts for matched logs."""
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

def read_and_compare_logs(file_path):
    """Read logs and compare them with malicious logs in MongoDB."""
    logs = read_logs(file_path)
    malicious_logs = get_malicious_logs_from_mongodb()
    malicious_messages = {log["message"] for log in malicious_logs}
    
    matched_logs = []
    for log in logs:
        log_message = log.strip()
        if log_message in malicious_messages:
            matched_logs.append(log_message)
    
    print(f"Found {len(matched_logs)} matched malicious logs.")
    return matched_logs

def train_on_new_logs(log_path):
    """Train the anomaly detector on new logs."""
    new_logs = read_logs(log_path)
    if new_logs:
        train_anomaly_detector(new_logs)

if __name__ == "__main__":
    # Define directories and log paths
    Log_Directory = "Log_Analysis/Collected_Logs"
    os.makedirs(Log_Directory, exist_ok=True)

    client_logs_path = "D:\elasticsearch\server_logs\server_logs.log"

    # Step 1: Read client logs and compare with malicious logs from MongoDB
    print("Comparing client logs with malicious logs...")
    matched_client_logs = read_and_compare_logs(client_logs_path)

    if matched_client_logs:
        print(f"Found malicious logs in client logs.")
        generate_alert(matched_client_logs)
    else:
        print("No known malicious logs found in client logs.")

    # Step 2: Train anomaly detector on normal logs
    print("Training anomaly detector...")
    normal_logs = ["Successful login", "File accessed", "User logged out"]
    train_anomaly_detector(normal_logs)

    train_on_new_logs(client_logs_path)

    # Step 3: Detect anomalies in client logs
    client_logs = read_logs(client_logs_path)
    
    if client_logs:
        anomalies = detect_anomalies(client_logs)
        if anomalies:
            print(f"Anomalous logs detected: {anomalies}")
            generate_alert(anomalies)
        else:
            print("No anomalies detected in client logs.")
    else:
        print("No client logs to analyze for anomalies.")
