from datetime import datetime
from pymongo import MongoClient
import os

# MongoDB connection
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]
alerts_collection = mongo_db["alerts"]


def read_and_compare_logs(file_path):
    if not os.path.exists(file_path):
        print(f"Error: Log file {file_path} does not exist")
        return []

    try:
        with open(file_path, "r") as file:
            logs = file.readlines()
            print(f"Read {len(logs)} logs from file {file_path}")
    except Exception as e:
        print(f"Error reading log file {file_path}: {e}")
        return []

    # Fetch existing malicious logs from MongoDB
    malicious_logs = get_malicious_logs_from_mongodb()
    malicious_messages = {log["message"] for log in malicious_logs}

    # Compare logs with malicious entries
    matched_logs = []
    for log in logs:
        log_message = log.strip()
        if log_message in malicious_messages:
            matched_logs.append(log_message)

    print(f"Found {len(matched_logs)} matched malicious logs.")
    return matched_logs


def get_malicious_logs_from_mongodb():
    try:
        return list(malicious_logs_collection.find({}, {"_id": 0, "message": 1}))
    except Exception as e:
        print(f"Error fetching malicious logs from MongoDB: {e}")
        return []


def update_malicious_logs_in_mongodb(logs):
    try:
        for log in logs:
            log_entry = {
                "message": log.strip(),
                "@timestamp": datetime.now().isoformat(),
            }
            # Upsert log into MongoDB
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
                "description": "A log entry matched known malicious patterns",
            }
            alerts_collection.insert_one(alert_entry)
        print(f"Generated {len(matched_logs)} alerts for malicious logs.")
    except Exception as e:
        print(f"Error generating alerts: {e}")


if __name__ == "__main__":
    # Define directories and log paths
    Log_Dirrectory = "Log_Analysis/Collected_Logs"
    os.makedirs(Log_Dirrectory, exist_ok=True)

    client_logs_path = "D:/elasticsearch/test.log"

    # Step 1: Read client logs and compare with malicious logs from MongoDB
    print("Comparing client logs with malicious logs...")
    matched_client_logs = read_and_compare_logs(client_logs_path)

    if matched_client_logs:
        print(f"Found malicious logs in client logs.")
        generate_alert(matched_client_logs)  # Generate alerts for matched logs
    else:
        print("No malicious logs found in client logs.")
