import os
import pymongo
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/" 
DATABASE_NAME = "log_database"
COLLECTION_NAME = "logs"

def connect_to_mongo():
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]
    return collection

def transfer_logs_to_mongo(log_directory):
    collection = connect_to_mongo()
    
    for root, _, files in os.walk(log_directory):
        for file in files:
            if file.endswith(".log"):  
                file_path = os.path.join(root, file)
                
                with open(file_path, "r") as log_file:
                    log_content = log_file.read()
                    
                    log_document = {
                        "filename": file,
                        "file_path": file_path,
                        "content": log_content
                    }
                    
                    collection.insert_one(log_document)
                    print(f"Transferred {file} to MongoDB.")

if __name__ == "__main__":
    log_directory = input("Enter the path to the log directory: ")
    transfer_logs_to_mongo(log_directory)
