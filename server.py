from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import shutil
import gzip
import tarfile
import cgi
import json
import io
from datetime import datetime
import re
from pymongo import MongoClient
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import secrets
import argparse

# Directories for storing logs and traffic
Log_Dirrectory = "Log_Analysis/Collected_Logs"
Mal_Traffic_Directory = "Traffic_Analysis/Captured_Malicious_Traffic"
os.makedirs(Log_Dirrectory, exist_ok=True)
os.makedirs(Mal_Traffic_Directory, exist_ok=True)

# MongoDB Setup
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]
alerts_collection = mongo_db["alerts"]
p_db = mongo_client["agent_db"]

# Anomaly detection model
anomaly_detector = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
scaler = StandardScaler()

# Functions for log analysis and anomaly detection
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
    features = extract_features(logs)
    if features.size == 0:
        print("No features to predict for anomaly detection.")
        return []

    features = scaler.transform(features)
    predictions = anomaly_detector.predict(features)
    anomalies = [log for log, pred in zip(logs, predictions) if pred == -1]
    return anomalies

def update_malicious_logs_in_mongodb(logs):
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

# HTTP Server for handling requests
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/yara':
            os.makedirs("Traffic_Analysis/Yara_Rules", exist_ok=True)
            with tarfile.open("Traffic_Analysis/Yara_Rules/Send.gz", "w:gz") as tar:
                tar.add("Traffic_Analysis/Yara_Rules/", arcname=os.path.basename("Traffic_Analysis/Yara_Rules/"))
            try:
                with open("Traffic_Analysis/Yara_Rules/Send.gz", 'rb') as file:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/gzip')
                    self.end_headers()
                    self.wfile.write(file.read())
            except IOError:
                self.send_error(404, 'File Not Found')
            os.remove("Traffic_Analysis/Yara_Rules/Send.gz")
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "Not Found"}')
        
    def do_POST(self):
        if self.path == '/upload_file':
            content_type = self.headers.get('Content-Type')        
            if content_type and 'multipart/form-data' in content_type:
                try:             
                    # Parse the form data
                    form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
                    token = form.getfirst('token')
                    collection = p_db['Agents']
                    query = {'token': token}
                    agent = collection.find_one(query)
                    if agent:
                        if 'file' in form:
                            file_item = form['file']
                            if file_item.file:
                                file_name = form.getfirst('file_name')
                                file_ext = form.getfirst('file_ext')
                                if file_ext == "pcap":
                                    file_path = os.path.join(Mal_Traffic_Directory, agent['Agent_Name'], file_name)  
                                    os.makedirs(os.path.join(Mal_Traffic_Directory, agent['Agent_Name']), exist_ok=True)                             
                                elif file_ext == "log":
                                    file_path = os.path.join(Log_Dirrectory, agent['Agent_Name'], file_name)
                                    os.makedirs(os.path.join(Log_Dirrectory, agent['Agent_Name']), exist_ok=True) 
                        
                                with open(file_path, 'wb') as output_file:
                                    shutil.copyfileobj(file_item.file, output_file)
                                # Check file size
                                file_size = os.path.getsize(file_path)
                                print(f"Received file size: {file_size} bytes")

                                if file_size == 0:
                                    raise ValueError("Received file is empty")

                                # Decompress the file
                                decompressed_file_path = file_path.rsplit('.', 1)[0]  # Remove .gz extension
                        
                                if file_ext == "log":
                                    existing_lines = set()
                                    try:
                                        with open(decompressed_file_path, 'r') as existing_file:
                                            existing_lines = set(existing_file.readlines())
                                    except FileNotFoundError:
                                        print(f"New Log Entry")
                                    with gzip.open(file_path, 'rb') as f_in:
                                        with open(decompressed_file_path, 'wb') as f_out:
                                            shutil.copyfileobj(f_in, f_out)
                                    new_lines = []
                                    with open(decompressed_file_path, 'r') as f:
                                        for line in f:
                                            if line not in existing_lines:
                                                new_lines.append(line.strip())   
                                    matched_client_logs = read_logs(new_lines)         
                                    if matched_client_logs:
                                        for log in matched_client_logs:
                                            a_db = mongo_client["Alerts"]
                                            if agent["Agent_Name"] not in a_db.list_collection_names():
                                                a_db.create_collection(agent["Agent_Name"])
                                            a_collection = a_db[agent['Agent_Name']]
                                            a_collection.insert_one({"date_time": datetime.now().isoformat(), "category": "mal_logs", "message": log, "severity": "moderate", "description": "logs in comparison with stored mal logs"}) 
                                    preprocessed_logs = new_lines
                                    anomalies = detect_anomalies(preprocessed_logs)
                                    if anomalies:
                                        update_malicious_logs_in_mongodb(anomalies)
                                        generate_alert(anomalies)
                                    print(anomalies)
                                if file_ext != "log":
                                    with gzip.open(file_path, 'rb') as f_in:
                                        with open(decompressed_file_path, 'wb') as f_out:
                                            shutil.copyfileobj(f_in, f_out)
                                os.remove(file_path)   
                                # Send response
                                self.send_response(200)
                                self.send_header('Content-type', 'application/json')
                                self.end_headers()
                                self.wfile.write(b'{"message": "File uploaded and processed successfully"}')
                    else:
                        self.send_response(401)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(b'{"error": "Agent not authorized"}')
                except Exception as e:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())
            else:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid request"}')

def run_server():
    server_address = ('localhost', 8000)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print('Server running at http://localhost:8000/')
    httpd.serve_forever()

# Main Function
if __name__ == "__main__":
    run_server()
