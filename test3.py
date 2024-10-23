from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest
import argparse
import shutil
import gzip
import tarfile
import cgi
import json
from datetime import datetime
import numpy as np

# MongoDB setup
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]
alerts_collection = mongo_db["alerts"]

# Initialize Isolation Forest for anomaly detection
anomaly_detector = IsolationForest(contamination=0.01, random_state=42)

# Directories for logs and traffic analysis
Log_Directory = "Log_Analysis/Collected_Logs"
Mal_Traffic_Directory = "Traffic_Analysis/Captured_Malicious_Traffic"
os.makedirs(Log_Directory, exist_ok=True)
os.makedirs(Mal_Traffic_Directory, exist_ok=True)

# Read logs from file
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

# Feature extraction for anomaly detection
def extract_features(logs):
    features = []
    for log in logs:
        log_length = len(log)
        error_count = log.lower().count("error")
        failed_count = log.lower().count("failed")
        features.append([log_length, error_count, failed_count])
    return np.array(features)

# Train anomaly detector
def train_anomaly_detector(normal_logs):
    features = extract_features(normal_logs)
    if features.size == 0:
        print("No features extracted for anomaly detector training.")
        return
    anomaly_detector.fit(features)
    print("Anomaly detector trained on normal logs.")

# Detect anomalies
def detect_anomalies(logs):
    features = extract_features(logs)
    if features.size == 0:
        print("No features to predict for anomaly detection.")
        return []
    predictions = anomaly_detector.predict(features)
    anomalies = [log for log, pred in zip(logs, predictions) if pred == -1]
    return anomalies

# Fetch malicious logs from MongoDB
def get_malicious_logs_from_mongodb():
    try:
        return list(malicious_logs_collection.find({}, {"_id": 0, "message": 1}))
    except Exception as e:
        print(f"Error fetching malicious logs from MongoDB: {e}")
        return []

# Update malicious logs in MongoDB
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

# Generate alert for matched logs
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

# Compare logs with malicious logs in MongoDB
def read_and_compare_logs(file_path):
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

# HTTP Server Handler
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
                    form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
                    token = form.getfirst('token')
                    collection = mongo_db['Agents']
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
                                    file_path = os.path.join(Log_Directory, agent['Agent_Name'], file_name)
                                    os.makedirs(os.path.join(Log_Directory, agent['Agent_Name']), exist_ok=True) 
                                     
                                with open(file_path, 'wb') as output_file:
                                    shutil.copyfileobj(file_item.file, output_file)
                                
                                file_size = os.path.getsize(file_path)
                                if file_size == 0:
                                    raise ValueError("Received file is empty")

                                decompressed_file_path = file_path.rsplit('.', 1)[0]
                                with gzip.open(file_path, 'rb') as f_in:
                                    with open(decompressed_file_path, 'wb') as f_out:
                                        shutil.copyfileobj(f_in, f_out)
                                os.remove(file_path)

                                if file_ext == "log":
                                    matched_client_logs = read_and_compare_logs(decompressed_file_path)
                                    if matched_client_logs:
                                        generate_alert(matched_client_logs)
                                
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(b'{"message": "File received and saved"}')
                    else:
                        self.send_response(403)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(b'{"message": "Not Valid Token"}')
                except Exception as e:
                    print(f'Error processing file: {e}')
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error": "Internal Server Error"}')
            else:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid Content-Type"}')
        elif self.path == "/alert":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                json_data = json.loads(post_data)
                token = json_data["token"]
                collection = mongo_db['Agents']
                query = {'token': token}
                agent = collection.find_one(query)
                if agent:
                    alerts_collection.delete_many({'category': json_data['category'], 'message': json_data['message']})
                    alerts_collection.insert_one({
                        "date_time": datetime.now().isoformat(),
                        "category": json_data['category'],
                        "message": json_data['message'],
                        "severity": json_data['severity'],
                        "description": json_data['description']
                    })
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"message": "Alert Received"}')
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON"}')
            except Exception as e:
                print(f"Error processing alert: {e}")
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Internal Server Error"}')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "Not Found"}')

# HTTP Server Setup
def run_server(host="0.0.0.0", port=8000):
    server_address = (host, port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Starting server on {host}:{port}")
    httpd.serve_forever()

# Main logic with argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analysis and Traffic Monitoring")
    parser.add_argument("--train", help="Path to normal logs for training", type=str)
    args = parser.parse_args()

    if args.train:
        normal_logs = read_logs(args.train)
        train_anomaly_detector(normal_logs)
    
    # Start the server
    run_server()
