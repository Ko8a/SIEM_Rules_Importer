import requests
from requests.auth import HTTPBasicAuth
import json
import dotenv
import os

dotenv.load_dotenv()

# Replace these variables with your own details
kibana_url = f"http://{os.getenv('ELK_HOST')}"
username = os.getenv('ELK_USERNAME')
password = os.getenv('ELK_PASSWORD')

# Create a session object
session = requests.Session()

def kibana_login(kibana_url, username, password):
    # Set the login URL
    login_url = f"{kibana_url}/login"

    # Perform the GET request to log in
    response = session.get(login_url, auth=HTTPBasicAuth(username, password))

    # Check the response
    if response.status_code == 200:
        print("Login successful!")
        return session
    else:
        print(f"Failed to log in. Status Code: {response.status_code}, Response: {response.text}")
        return None

def get_kibana_alerts(kibana_url, session):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }

    # Construct the URL for retrieving alerting rules
    url = f"{kibana_url}/api/alerting/rules/_find"

    # Perform the GET request to retrieve the alerting rules
    response = session.get(url, headers=headers)

    # Check the response
    if response.status_code == 200:
        alerts = response.json()
        print(json.dumps(alerts, indent=2))
    else:
        print(f"Failed to retrieve alerts. Status Code: {response.status_code}, Response: {response.text}")
        
def export_kibana_alerts(kibana_url, session, export_filepath, username, password):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }

    # Construct the URL for retrieving alerting rules
    url = f"{kibana_url}/api/detection_engine/rules/_find?page=1&per_page=1300"

    # Perform the GET request to retrieve the alerting rules
    response = session.get(url, headers=headers, auth=HTTPBasicAuth(username, password))

    # Check the response
    if response.status_code == 200:
        alerts = response.json()
        # print(json.dumps(alerts, indent=2))
        with open(export_filepath, "w", encoding="utf-8") as json_file:
            json.dump(alerts["data"], json_file, indent=4)
        print(f"Rules were exported: {len(alerts["data"])}")
    else:
        print(f"Failed to retrieve alerts. Status Code: {response.status_code}, Response: {response.text}")

# Example usage
if __name__ == "__main__":
    # Login to Kibana and create a session
    session = kibana_login(kibana_url, username, password)

    if session:
        # Retrieve and print the alerting rules
        export_filepath = "rules_export.json"  # Specify where to save the exported rules
        export_kibana_alerts(kibana_url, session, export_filepath, username, password)
