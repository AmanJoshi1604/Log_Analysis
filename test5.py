import logging
import numpy as np
import re
import hashlib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
from pymongo import MongoClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MongoDB client setup
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]
alerts_collection = mongo_db["alerts"]

# Machine learning model and scaler
anomaly_detector = IsolationForest(contamination=0.01, random_state=42)
scaler = StandardScaler()

def preprocess_logs(logs):
    preprocessed_logs = []
    for log in logs:
        log = log.lower()
        log = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '', log)
        preprocessed_logs.append(log)
    return preprocessed_logs

def read_normal_logs(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Normal logs file {file_path} does not exist")
        return []
    try:
        with open(file_path, "r") as file:
            logs = [log.strip() for log in file if log.strip()]
            logging.info(f"Read {len(logs)} normal logs from file {file_path}")
            return logs
    except Exception as e:
        logging.error(f"Error reading normal logs file {file_path}: {e}")
        return []

def extract_features(logs):
    features = []
    for log in logs:
        log_length = len(log)
        error_count = log.lower().count("error")
        failed_count = log.lower().count("fail")
        warning_count = log.lower().count("warn")
        timestamp_feature = 1 if "timestamp" in log.lower() else 0
        ip_addresses = len(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log))
        special_chars = sum(1 for char in log if not char.isalnum() and char not in ' ')
        
        features.append([log_length, error_count, failed_count, warning_count, timestamp_feature, ip_addresses, special_chars])
    
    return np.array(features)

def train_AI_Scanner(normal_logs):
    features = extract_features(normal_logs)
    if features.size == 0:
        logging.warning("No features extracted for training AI Scanner.")
        return

    scaled_features = scaler.fit_transform(features)
    anomaly_detector.fit(scaled_features)
    logging.info("AI Scanner trained on normal logs.")

def generate_hash(message):
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def update_malicious_logs_in_mongodb(logs):
    try:
        for log in logs:
            log_hash = generate_hash(log)
            log_entry = {
                "message": log.strip(),
                "category": "Malicious",
                "@timestamp": datetime.now().isoformat(),
                "hash": log_hash  
            }
            malicious_logs_collection.update_one(
                {"hash": log_hash}, {"$set": log_entry}, upsert=True
            )
        logging.info(f"Updated {len(logs)} malicious logs in MongoDB")
    except Exception as e:
        logging.error(f"Error updating malicious logs in MongoDB: {e}")

def create_alerts(logs):
    try:
        for log in logs:
            alert_entry = {
                "message": log,
                "severity": "High",
                "category": "Malicious Log Detected",
                "timestamp": datetime.now().isoformat(),
                "description": "A log entry matched known malicious patterns or was detected as malicious",
            }
            alerts_collection.insert_one(alert_entry)
        logging.info(f"Created alerts for {len(logs)} malicious logs")
    except Exception as e:
        logging.error(f"Error creating alerts in MongoDB: {e}")

def detect_anomalies(logs):
    features = extract_features(logs)
    if features.size == 0:
        logging.warning("No features to predict malicious logs.")
        return []

    try:
        if not hasattr(scaler, 'mean_'):  
            logging.error("Scaler has not been fitted. Please train the AI Scanner first.")
            return []
        scaled_features = scaler.transform(features)
    except Exception as e:
        logging.error(f"Error during feature scaling: {e}")
        return []

    predictions = anomaly_detector.predict(scaled_features)
    anomalies = [log for log, pred in zip(logs, predictions) if pred == -1]

    return anomalies

def main_pipeline(normal_logs_path):
    logging.info("Reading logs...")
    logs = read_normal_logs(normal_logs_path)
    
    if not logs:
        logging.warning("No logs found.")
        return

    logs = preprocess_logs(logs)
    
    logging.info("Training AI Scanner on normal logs...")
    train_AI_Scanner(logs)
    
    logging.info("Detecting malicious logs...")
    anomalies = detect_anomalies(logs)
    
    if anomalies:
        logging.info(f"Detected {len(anomalies)} malicious logs.")
        logging.info("Updating MongoDB with new malicious logs...")
        update_malicious_logs_in_mongodb(anomalies)
        
        logging.info("Creating alerts for detected malicious logs...")
        create_alerts(anomalies)
    else:
        logging.info("No malicious logs detected.")

if __name__ == "__main__":
    normal_logs_path = "D:\elasticsearch\malicious_logs\malicious_logs.log"
    main_pipeline(normal_logs_path)
