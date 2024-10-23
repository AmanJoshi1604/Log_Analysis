import os
import json
import csv
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionTimeout, TransportError, ConnectionError
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Elasticsearch client
es = Elasticsearch(
    [{'host': 'localhost', 'port': 9200, 'scheme': 'https'}],
    basic_auth=('elastic', 'zswNiQjnMnc0Bvg2vjYj'),
    ca_certs='C:\\elasticsearch\\kibana-8.14.2\\data\\ca_1720367038865.crt',
    request_timeout=300  # Increased request timeout
)

def parse_log_entry(line, file_extension):
    try:
        stripped_line = line.strip()
        if file_extension == '.json':
            return json.loads(stripped_line)
        elif file_extension == '.csv':
            reader = csv.DictReader([stripped_line])
            return next(reader)
        elif file_extension == '.log':
            parts = stripped_line.split(' ')
            log_entry = {}
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    log_entry[key] = value
                else:
                    log_entry.setdefault("message", "")
                    log_entry["message"] += part + " "
            log_entry["message"] = log_entry["message"].strip()
            return log_entry
        else:
            return {"message": stripped_line}
    except Exception as e:
        print(f"Error parsing log entry: {e}")
        return None

def import_logs(file_path, index_name):
    file_extension = os.path.splitext(file_path)[1].lower()
    actions = []
    batch_size = 50
    retry_attempts = 3
    with open(file_path, 'r') as file:
        for line_number, line in enumerate(file, start=1):
            log_entry = parse_log_entry(line, file_extension)
            if log_entry:
                action = {
                    "_index": index_name,
                    "_source": log_entry
                }
                actions.append(action)
                
                if len(actions) >= batch_size:
                    for attempt in range(retry_attempts):
                        try:
                            print(f"Indexing {len(actions)} entries to Elasticsearch...")
                            helpers.bulk(es, actions)
                            actions.clear()
                            break
                        except (helpers.BulkIndexError, ConnectionTimeout, TransportError, ConnectionError) as bulk_error:
                            print(f"Error indexing batch: {bulk_error}")
                            if attempt < retry_attempts - 1:
                                print(f"Retrying {attempt + 1}/{retry_attempts}...")
                                time.sleep(5)
                            else:
                                print(f"Failed to index batch after {retry_attempts} attempts.")
                                actions.clear()

    if actions:
        for attempt in range(retry_attempts):
            try:
                print(f"Indexing {len(actions)} remaining entries to Elasticsearch...")
                helpers.bulk(es, actions)
                break
            except (helpers.BulkIndexError, ConnectionTimeout, TransportError, ConnectionError) as bulk_error:
                print(f"Error indexing batch: {bulk_error}")
                if attempt < retry_attempts - 1:
                    print(f"Retrying {attempt + 1}/{retry_attempts}...")
                    time.sleep(5)
                else:
                    print(f"Failed to index batch after {retry_attempts} attempts.")

if __name__ == "__main__":
    log_file_paths = [
        "C:\\elasticsearch\\client_logs\\client_logs.json",
        "C:\\elasticsearch\\client_logs\\client_logs.csv",
        "C:\\elasticsearch\\client_logs\\client_logs.log"
    ]
    index_name = "client_logs"

    for log_file_path in log_file_paths:
        if os.path.exists(log_file_path):
            print(f"Log file {log_file_path} found.")
            import_logs(log_file_path, index_name)
        else:
            print(f"Log file {log_file_path} does not exist.")
