import os
import logging
from pymongo import MongoClient
import re
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
import urllib3
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "agent_logs"

# Initialize MongoDB client
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

# Regex to parse log lines
LOG_REGEX = re.compile(r'^(?P<date>\d{2}/\d{2}/\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<logger>[^:]+): (?P<message>.+)$')

# Elasticsearch setup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
es = Elasticsearch(
    [{'host': 'localhost', 'port': 9200, 'scheme': 'https'}],
    basic_auth=('elastic', 'zswNiQjnMnc0Bvg2vjYj'),
    ca_certs='C:\\elasticsearch\\kibana-8.14.2\\data\\ca_1720367038865.crt'
)

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
            log_data['timestamp'] = datetime.strptime(log_data['date'] + ' ' + log_data['time'], '%d/%m/%y %H:%M:%S')
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
    Fetch log lines from an agent's Elasticsearch index.
    """
    index_name = f"{agent_name}_logs"
    query_body = {
        "query": {
            "match_all": {}
        }
    }
    try:
        response = es.search(index=index_name, body=query_body)
        hits = response['hits']['hits']
        log_lines = [hit['_source']['message'] for hit in hits if 'message' in hit['_source']]
        return log_lines
    except Exception as e:
        logging.error(f"Error fetching logs from Elasticsearch index '{index_name}': {e}")
        return []

def scan_directory_once():
    """
    Scan MongoDB for existing agents and logs.
    """
    agent_collections = db.list_collection_names()
    for agent in agent_collections:
        logging.info(f"Scanning logs for agent: {agent}")
        logs = db[agent].find()
        for log in logs:
            formatted_log = (
                f"Agent: {log.get('agent_name', 'N/A')}\n"
                f"Timestamp: {log.get('timestamp', 'N/A')}\n"
                f"Level: {log.get('level', 'N/A')}\n"
                f"Logger: {log.get('logger', 'N/A')}\n"
                f"Message: {log.get('message', 'N/A')}\n"
                f"{'-'*50}"
            )
            logging.info(formatted_log)


def add_new_agent(agent_name):
    if not agent_name.isalnum():
        logging.error(f"Invalid agent name: {agent_name}. Only alphanumeric characters are allowed.")
        return
    
    # Create a new log directory for the agent
    create_agent_log_directory(agent_name)
    
    # Fetch logs from the agent's Elasticsearch index
    log_lines = fetch_logs_from_agent(agent_name)
    
    # Process the fetched log lines and store them in MongoDB
    process_log_file(agent_name, log_lines)

def add_timestamp_to_logs(index_name):
    try:
        query_body = {
            "size": 1000,
            "query": {
                "match_all": {}
            }
        }
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

def fetch_logs(index_name, query_body):
    try:
        response = es.search(index=index_name, body=query_body)
        hits = response['hits']['hits']
        logging.info(f"Fetched {len(hits)} logs from index '{index_name}'")

        for hit in hits:
            log_id = hit['_id']
            timestamp = hit['_source'].get('@timestamp', 'N/A')
            message = hit['_source'].get('message', 'N/A')
            
            logging.info(f"Log ID: {log_id}")
            logging.info(f"Timestamp: {timestamp}")
            logging.info(f"Message: {message}")
            logging.info("-" * 50)

    except Exception as e:
        logging.error(f"Error fetching logs from '{index_name}': {e}")

def create_agent_log_directory(agent_name):
    dir_path = os.path.join('agent_logs', agent_name)
    os.makedirs(dir_path, exist_ok=True)
    logging.info(f"Created log directory for agent: {agent_name}")

def import_agent_logs(agent_name):
    dir_path = os.path.join('agent_logs', agent_name)
    if not os.path.exists(dir_path):
        logging.error(f"Log directory for agent {agent_name} does not exist.")
        return

    for log_file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, log_file)
        logs = read_log_file(file_path)

        if logs:
            es_logs = [{"_index": agent_name, "_source": parse_log_line(log)} for log in logs if parse_log_line(log)]
            if es_logs:
                helpers.bulk(es, es_logs)
                logging.info(f"Imported logs from {file_path} to Elasticsearch index {agent_name}")

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
