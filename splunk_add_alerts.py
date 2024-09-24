import requests
import json
import time
import dotenv
import os

# Loading envirement variables
dotenv.load_dotenv()

# Splunk server details
splunk_host = os.getenv("SPLUNK_LOCAL_HOST")
splunk_port = "8089"  # Management port
username = os.getenv("SPLUNK_LOCAL_USERNAME")
password = os.getenv("SPLUNK_LOCAL_PASSWORD")

# REST API endpoints
auth_endpoint = f"{splunk_host}:{splunk_port}/services/auth/login"
alerts_endpoint = f"{splunk_host}:{splunk_port}/services/saved/searches"

# Create a session to persist credentials
session = requests.Session()

def get_splunk_auth_token():
    # Log in to Splunk and get the session key
    data = {
        "username": username,
        "password": password
    }
    response = session.post(auth_endpoint, data=data, verify=False)
    if response.status_code == 200:
        session_key = response.text.split("<sessionKey>")[1].split("</sessionKey>")[0]
        session.headers.update({"Authorization": f"Splunk {session_key}"})
        return session_key
    else:
        raise Exception(f"Failed to authenticate: {response.text}")

def add_alert_rule(alert_name, search_query, cron_schedule, alert_type="number of events", alert_threshold="0", action="list", alert_expires="1d", time_range="1", trigger_type="1", alert_severity="4"):
    # Add a new alert rule with specific configurations
    data = {
        "name": alert_name,
        "search": search_query,
        "cron_schedule": cron_schedule,
        "is_scheduled": "1",
        "alert_type": alert_type,
        "alert_comparator": "greater than",
        "alert_threshold": alert_threshold,
        "actions": action,  # Add to the Triggered alerts list
        "alert.expires": alert_expires,  # Set expiration to 60 days
        "dispatch.earliest_time": f"-{time_range}m",  # Set time range to "Last 1 minute"
        "dispatch.latest_time": "now",
        "alert.track": trigger_type,
        "alert.severity": alert_severity,  # Trigger "Once"
    }
    response = session.post(alerts_endpoint, data=data, verify=False)
    
    if response.status_code == 201:
        print(f"Alert rule '{alert_name}' created successfully and will appear in Triggered Alerts.")
    if response.status_code == 409:
        print("WARNING! Alert with same name exists")
        counter = 1
        isSuccess = False
        while not isSuccess:
            data["name"] = alert_name + f"-{counter}"
            response = session.post(alerts_endpoint, data=data, verify=False)
            if response.status_code == 201:
                isSuccess = True
                print(f"ALERT was added under the name: {data["name"]}")
            else:
                counter += 1
    else:
        print(f"Failed to create alert: {data["name"]}")

def main():
    get_splunk_auth_token()

    #----- IMPORT GTFOBINS RULES ------
    with open("data/new_gtfobins.json", "r") as file:
        dict_test = json.loads(file.read())

    for key in dict_test:
        print('name:', key['name'])
        print('query:',key['query'])
        print("Adding new alert")
        add_alert_rule(
            alert_name=f"(Linux) {key['name']}",
            search_query=key['query'],
            cron_schedule="* * * * *",  # Run every 5 minutes
            alert_type="number of events",
            alert_threshold="0",  # Trigger alert if more than 10 events occur
            alert_expires="60d",  # Alert live time
        )
        time.sleep(1)
        print('-'*50)
    
    #----- IMPORT LOLBINS RULES ------
    with open("data/LOLbins.json", "r") as file:
        dict_test = json.loads(file.read())

    for key in dict_test:
        print('name:', key['name'])
        print('query:',key['query'])
        print("Adding new alert")
        add_alert_rule(
            alert_name=f"(Windows) {key['name']}",
            search_query=key['query'],
            cron_schedule="* * * * *",  # Run every 5 minutes
            alert_type="number of events",
            alert_threshold="0",  # Trigger alert if more than 10 events occur
            alert_expires="60d",  # Alert live time
        )
        time.sleep(1)
        print('-'*50)

if __name__ == "__main__":
    main()
