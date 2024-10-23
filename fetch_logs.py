from datetime import datetime
from elasticsearch import Elasticsearch, helpers
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

es = Elasticsearch(
    [{'host': 'localhost', 'port': 9200, 'scheme': 'https'}],
    basic_auth=('elastic', 'zswNiQjnMnc0Bvg2vjYj'),
    ca_certs='C:\\elasticsearch\\kibana-8.14.2\\data\\ca_1720367038865.crt'
)

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
            print(f"Added @timestamp to {len(actions)} logs in index '{index_name}'")
        # Remove the else block that prints the message when no logs are found without @timestamp

    except Exception as e:
        print(f"Error adding @timestamp to logs in '{index_name}': {e}")

def fetch_logs(index_name, query_body):
    try:
        response = es.search(index=index_name, body=query_body)
        hits = response['hits']['hits']
        print(f"Fetched {len(hits)} logs from index '{index_name}'")

        for hit in hits:
            log_id = hit['_id']
            timestamp = hit['_source'].get('@timestamp', 'N/A')
            message = hit['_source'].get('message', 'N/A')
            
            print(f"Log ID: {log_id}")
            print(f"Timestamp: {timestamp}")
            print(f"Message: {message}")
            print("-" * 50)

    except Exception as e:
        print(f"Error fetching logs from '{index_name}': {e}")

if __name__ == "__main__":
    client_logs_index = "client_logs"
    server_logs_index = "server_logs"

    # Process client logs
    add_timestamp_to_logs(client_logs_index)
    query_body_client_logs = {
        "query": {
            "match_all": {}
        }
    }
    fetch_logs(client_logs_index, query_body_client_logs)

    # Process server logs
    add_timestamp_to_logs(server_logs_index)
    query_body_server_logs = {
        "query": {
            "match_all": {}
        }
    }
    fetch_logs(server_logs_index, query_body_server_logs)
