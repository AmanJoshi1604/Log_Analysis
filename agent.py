import os
import logging
from pymongo import MongoClient
import re
from datetime import datetime, date
import hashlib
import requests
import json
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import gzip
import shutil
from pathlib import Path
import threading
from Traffic_Analysis import Traffic_Analysis_alpha as TA
import base64
import tarfile
from elasticsearch import Elasticsearch, helpers
import urllib3
import time

from lib_shared.common_config import *

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Get the current date
current_date = date.today()

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "agent_logs"
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

# Elasticsearch setup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
es = Elasticsearch(
    [{'host': 'localhost', 'port': 9200, 'scheme': 'https'}],
    basic_auth=('elastic', 'zswNiQjnMnc0Bvg2vjYj'),
    ca_certs='C:\\elasticsearch\\kibana-8.14.2\\data\\ca_1720367038865.crt',
    request_timeout=120
)

malicious_logs_collection = db["malicious_logs"]

# Define paths and URLs
upload_server_path = f'http://{server_ip}:{server_port}/upload_file'
get_yara_url = f'http://{server_ip}:{server_port}/yara'
pcap_file_to_watch = f'Traffic_Analysis/Malicious_Capture/traffic_{current_date}.pcap'
log_files_to_watch.append(pcap_file_to_watch)

# Regex to parse log lines
LOG_REGEX = re.compile(r'^(?P<date>\d{2}/\d{2}/\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<logger>[^:]+): (?P<message>.+)$')

def store_log_in_mongodb(agent_name, log_data):
    try:
        collection = db[agent_name]
        collection.insert_one(log_data)
        logging.info(f"Stored log in MongoDB for agent: {agent_name}")
    except Exception as e:
        logging.error(f"Error storing log in MongoDB for agent {agent_name}: {e}")

def process_log_file(agent_name, log_lines):
    for line in log_lines:
        log_data = parse_log_line(line.strip())
        if log_data:
            log_data["agent_name"] = agent_name
            store_log_in_mongodb(agent_name, log_data)
        else:
            logging.error(f"Failed to normalize log line: {line.strip()}")

def parse_log_line(log_line):
    """
    Parse a log line into a structured JSON object.
    """
    match = LOG_REGEX.match(log_line)
    if match:
        log_data = match.groupdict()
        try:
            log_data['timestamp'] = datetime.strptime(log_data['date'] + ' ' + log_data['time'], '%y/%m/%d %H:%M:%S')
            del log_data['date']
            del log_data['time']
        except ValueError as e:
            logging.error(f"Error parsing date/time: {e}")
            return None
        return log_data
    else:
        return None

def fetch_logs_from_agent(agent_name):
    """
    Fetch log lines from an agent's system. This function is a placeholder and should be replaced
    with the actual implementation to fetch logs from the agent.
    """
    # For example, this might be an SSH command or file read operation
    # This is just a placeholder for demonstration purposes
    log_lines = [
        "17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Registered signal handlers for [TERM, HUP, INT]",
        "17/06/09 20:10:40 INFO spark.SecurityManager: Changing view acls to: yarn,curi",
        # Add more log lines here if needed
    ]
    return log_lines

def scan_directory_once():
    # Scan MongoDB for existing agents and logs
    agent_collections = db.list_collection_names()
    for agent in agent_collections:
        logging.info(f"Scanning logs for agent: {agent}")
        logs = db[agent].find()
        for log in logs:
            logging.info(log)

def add_new_agent(agent_name):
    if not agent_name.isalnum():
        logging.error(f"Invalid agent name: {agent_name}. Only alphanumeric characters are allowed.")
        return
    
    # Fetch logs from the agent's system
    log_lines = fetch_logs_from_agent(agent_name)
    
    # Process the fetched log lines and store them in MongoDB
    process_log_file(agent_name, log_lines)

# Function to add timestamp to logs
def add_timestamp_to_logs(index_name):
    try:
        query_body = {"size": 1000, "query": {"match_all": {}}}
        response = es.search(index=index_name, body=query_body)
        hits = response['hits']['hits']

        actions = []
        for hit in hits:
            doc_id = hit['_id']
            doc = hit['_source']
            if '@timestamp' not in doc:
                doc['@timestamp'] = datetime.now().isoformat()
                action = {
                    "_op_type": "update",
                    "_index": index_name,
                    "_id": doc_id,
                    "doc": {"@timestamp": doc['@timestamp']}
                }
                actions.append(action)

        if actions:
            helpers.bulk(es, actions)
            logging.info(f"Added @timestamp to {len(actions)} logs in index '{index_name}'")
    except Exception as e:
        logging.error(f"Error adding @timestamp to logs in '{index_name}': {e}")

# Function to fetch logs
def fetch_logs(index_name, query_body):
    try:
        response = es.search(index=index_name, body=query_body)
        hits = response['hits']['hits']
        logging.info(f"Fetched {len(hits)} logs from index '{index_name}'")
        return hits
    except Exception as e:
        logging.error(f"Error fetching logs from '{index_name}': {e}")
        return []

# Function to read log file
def read_log_file(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Error reading log file {file_path}: File does not exist")
        return []
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
            logging.info(f"Read {len(logs)} logs from file {file_path}")
            return logs
    except Exception as e:
        logging.error(f"Error reading log file {file_path}: {e}")
        return []

# Function to update malicious logs in MongoDB
def update_malicious_logs_in_mongodb(logs):
    for log in logs:
        log_entry = {
            "message": log.strip(),
            "@timestamp": datetime.now().isoformat()
        }
        malicious_logs_collection.update_one(
            {"message": log_entry["message"]},
            {"$set": log_entry},
            upsert=True
        )

# Function to get malicious logs from MongoDB
def get_malicious_logs_from_mongodb():
    return list(malicious_logs_collection.find({}, {"_id": 0, "message": 1}))

# Function to compare logs with malicious logs
def compare_logs_with_malicious_logs(logs, malicious_logs):
    malicious_messages = {log["message"] for log in malicious_logs}
    matched_logs = [log for log in logs if log["_source"]["message"] in malicious_messages]
    return matched_logs

# Watchdog event handler
class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def on_modified(self, event):
        if event.src_path == self.file_path:
            logging.info(f'File {self.file_path} has been modified.')
            send_log_file(self.file_path)

# Function to send log file to the central server
def send_log_file(file_path):
    try:
        compressed_file_path = Path(file_path).with_suffix('.gz')
        with open(file_path, 'rb') as f:
            with gzip.open(compressed_file_path, 'wb') as gz_file:
                shutil.copyfileobj(f, gz_file)

        with open(compressed_file_path, 'rb') as f:
            files = {'file': (compressed_file_path.name, f, 'application/gzip')}
            data = {'file_name': compressed_file_path.name, 'file_ext': file_path.rsplit('.', 1)[1], 'token': auth_token}
            response = requests.post(upload_server_path, files=files, data=data)
            if response.status_code == 200:
                logging.info(f'Successfully sent {file_path} to {upload_server_path}')
            else:
                logging.error(f'Failed to send {file_path} - Status code: {response.status_code}')

        os.remove(compressed_file_path)
    except Exception as e:
        logging.error(f'Error sending {file_path}: {e}')

# Function to get Yara rules
def get_yara_rules():
    try:
        with requests.get(get_yara_url, stream=True) as r:
            r.raise_for_status()
            with open('Traffic_Analysis/yara_rules/yara.gz', 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

        yara_gz_path = 'Traffic_Analysis/yara_rules/yara.gz'
        yara_path = 'Traffic_Analysis/yara_rules/yara'
        with gzip.open(yara_gz_path, 'rb') as f_in:
            with open(yara_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(yara_gz_path)

        with tarfile.open(yara_path, 'r') as tar:
            tar.extractall(path='Traffic_Analysis/yara_rules/')
        os.remove(yara_path)

        logging.info("Yara rules downloaded and extracted successfully.")
    except Exception as e:
        logging.error(f"Error downloading Yara rules: {e}")

# Function to create a new agent log directory
def create_agent_log_directory(agent_name):
    dir_path = os.path.join('agent_logs', agent_name)
    os.makedirs(dir_path, exist_ok=True)
    logging.info(f"Created log directory for agent: {agent_name}")

# Function to import agent logs into MongoDB and Elasticsearch
def import_agent_logs(agent_name):
    dir_path = os.path.join('agent_logs', agent_name)
    if not os.path.exists(dir_path):
        logging.error(f"Log directory for agent {agent_name} does not exist.")
        return

    for log_file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, log_file)
        logs = read_log_file(file_path)

        if logs:
            for log in logs:
                log_data = parse_log_line(log)
                if log_data:
                    store_log_in_mongodb(agent_name, log_data)

            es_logs = [{"_index": agent_name, "_source": parse_log_line(log)} for log in logs if parse_log_line(log)]
            if es_logs:
                helpers.bulk(es, es_logs)
                logging.info(f"Imported logs from {file_path} to Elasticsearch index {agent_name}")

# Main function
def main():
    parser = argparse.ArgumentParser(description='Agent Log Monitoring and Analysis')
    parser.add_argument('--scan', action='store_true', help='Scan logs from MongoDB')
    parser.add_argument('--add-agent', metavar='AGENT_NAME', type=str, help='Add a new agent and fetch its logs')
    parser.add_argument('--create-directory', metavar='AGENT_NAME', type=str, help='Create a new log directory for an agent')
    parser.add_argument('--import-logs', metavar='AGENT_NAME', type=str, help='Import logs of an agent into MongoDB and Elasticsearch')

    args = parser.parse_args()

    if args.scan:
        scan_directory_once()
    elif args.add_agent:
        add_new_agent(args.add_agent)
    elif args.create_directory:
        create_agent_log_directory(args.create_directory)
    elif args.import_logs:
        import_agent_logs(args.import_logs)
    else:
        logging.error("No valid arguments provided. Use --help for more information.")

if __name__ == '__main__':
    main()
