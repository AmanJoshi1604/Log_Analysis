# Log Analysis Tool

## Overview

The **Log Analysis Tool** is designed to collect, process, analyze, and visualize logs from various sources such as servers, applications, and network devices. It can detect anomalies, identify potential threats, and provide actionable insights from logs by integrating with databases like **MongoDB** and using machine learning techniques for log analysis.

This tool is modular and allows customization for different log formats, sources, and analysis requirements. It also supports sending alerts based on predefined rules or anomaly detection results.

---

## Features

- **Log Collection**: Supports multiple log collectors such as Filebeat, Winlogbeat, and custom Python scripts.
- **Log Parsing**: Uses Grok, Regular Expressions, and custom parsers to extract structured data from unstructured logs.
- **Database Integration**: Supports MongoDB for log storage and retrieval, with PyMongo for database operations.
- **Anomaly Detection**: Implements machine learning algorithms (e.g., Isolation Forest) to detect unusual patterns.
- **Alerts**: Sends alerts via email, Slack, or SMS when suspicious activity is detected.

---

## Requirements

### Software Requirements

- **Python** 3.8+
- **MongoDB** (for log storage)
- **Elasticsearch** (optional, for ELK stack integration)
- **Grafana** (optional, for visualization)
- **Fluentd / Filebeat / Logstash** (for log collection)
- **SMTP / Slack API** (for alerts)

### Python Dependencies

The following Python libraries are required to run this tool:

- `pymongo`
- `scikit-learn`
- `pandas`
- `numpy`
- `matplotlib`

To install the required Python libraries, run:

```bash
pip install -r requirements.txt
```

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/AmanJoshi1604/Log_Analysis.git
cd Log-Analysis-Tool
```

### 2. Configure MongoDB

Make sure MongoDB is installed and running on your local machine or a remote server. Modify the `config.py` file to include your MongoDB connection string:

```python
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "log_analysis"
COLLECTION_NAME = "logs"
```

### 3. Set Up Log Collection

Configure your log collector to forward logs to MongoDB or another destination.

### 4. Run the Log Analysis Program

Once MongoDB and the log collector are configured, you can start analyzing the logs:

```bash
python log_analysis.py
```

---

## Usage

### CLI Commands

The log analysis tool provides a set of command-line options for various operations. You can use the following commands:

- **Collect Logs**:
  
  ```bash
  python log_analysis.py --collect
  ```

- **Analyze Logs**:
  
  ```bash
  python log_analysis.py --analyze
  ```

- **Detect Anomalies**:
  
  ```bash
  python log_analysis.py --detect-anomalies
  ```

### Configuration

You can configure various settings, such as alert thresholds, log formats, and alert methods, in the `config.py` file.

---

## Customization

### Adding New Log Parsers

If you want to add a custom log parser, you can do so by modifying the `parsers.py` file. Here's an example of adding a new parser:

```python
def custom_parser(log_line):
    # Extract relevant data from log_line
    parsed_data = {}
    # Parsing logic here
    return parsed_data
```

## Machine Learning for Anomaly Detection

The tool includes a machine learning module for detecting anomalies in logs using the **Isolation Forest** algorithm from `scikit-learn`. To adjust the sensitivity of anomaly detection, you can modify the contamination parameter:

```python
from sklearn.ensemble import IsolationForest

def detect_anomalies(logs):
    model = IsolationForest(contamination=0.05)  # Adjust contamination as needed
    model.fit(logs)
    return model.predict(logs)
```

---

## Alerts and Notifications

Alerts are sent when certain conditions (e.g., anomalies or predefined log patterns) are met. You can customize the alert thresholds and recipients in the `config.py` file.
