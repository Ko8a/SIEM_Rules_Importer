import requests
import json
import time
import urllib3
import dotenv
import os

# Loading envirement variables
dotenv.load_dotenv()

# Disable SSL Warnings
urllib3.disable_warnings()

# Splunk server details
splunk_local_host = os.getenv("SPLUNK_LOCAL_HOST")
splunk_port = "8089"  # Default Management port
username_local = os.getenv("SPLUNK_LOCAL_USERNAME")
password_local = os.getenv("SPLUNK_LOCAL_PASSWORD")

# Splunk server details
splunk_NEW_host = os.getenv("SPLUNK_NEW_HOST")
username_GTS = os.getenv("SPLUNK_NEW_USERNAME")
password_GTS = os.getenv("SPLUNK_NEW_PASSWORD")


# REST API endpoints
auth_endpoint_local = f"{splunk_local_host}:{splunk_port}/services/auth/login"
alerts_endpoint_local = f"{splunk_local_host}:{splunk_port}/services/saved/searches"

# REST API endpoints
auth_endpoint_GTS = f"{splunk_NEW_host}:{splunk_port}/services/auth/login"
alerts_endpoint_GTS = f"{splunk_NEW_host}:{splunk_port}/services/saved/searches"

# Create a session to persist credentials
session_Local = requests.Session()
session_GTS = requests.Session()

def get_splunk_auth_token(username, password, auth_endpoint, session):
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
    
def get_all_alert_rules(alerts_endpoint, session):
    # Get all saved searches (alerts)
    params = {
        "output_mode": "json",
        "count": 0
    }
    response = session.get(alerts_endpoint, params=params, verify=False)
    
    if response.status_code == 200:
        alerts = response.json().get("entry", [])
        alerts_list = []

        for alert in alerts:
            name = alert.get("name")
            search_query = alert.get("content", {}).get("search")
            severity = alert.get("content", {}).get("alert.severity")
            alerts_list.append({
                "name": name,
                "query": search_query,
                "sevirity": severity
            })

        # Save the alerts to a JSON file
        with open("data/alerts.json", "w") as json_file:
            json.dump(alerts_list, json_file, indent=4)

        print(f"Saved {len(alerts_list)} alerts to alerts.json")
        return alerts_list
    else:
        raise Exception(f"Failed to retrieve alerts: {response.text}")
    
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
        # "sharing": "global",  # Set sharing to All Apps
        # "perms.read": "*",  # Set read permissions for everyone
        # "perms.write": "*",  # Set write permissions for everyone
    }
    response = session_GTS.post(alerts_endpoint_GTS, data=data, verify=False)
    
    if response.status_code == 201:
        print(f"Alert rule '{alert_name}' created successfully and will appear in Triggered Alerts.")
    elif response.status_code == 409:
        print("WARNING! Alert with same name exists")
        counter = 1
        isSuccess = False
        while not isSuccess:
            data["name"] = alert_name + f"-{counter}"
            response = session_GTS.post(alerts_endpoint_GTS, data=data, verify=False)
            if response.status_code == 201:
                isSuccess = True
                print(f"ALERT was added under the name: {data["name"]}")
            else:
                counter += 1
    else:
        print(f"Failed to create alert: {data["name"]}. Error: {response.text}")
        
def export_rules():
    get_splunk_auth_token(username=username_local, password=password_local, auth_endpoint=auth_endpoint_local, session=session_Local)
    
    allerts_list = get_all_alert_rules(alerts_endpoint=alerts_endpoint_local, session=session_Local)
    
    if allerts_list:
        print("SUCCESS! Alerts was successfullt exported")
        return True
    
    else:
        print("ERROR! Alerts wasn't exported")
        return False
        
def import_rules():
    with open("data/new_alerts.json", "r") as file:
        allerts_list = json.loads(file.read())

    get_splunk_auth_token(username=username_GTS, password=password_GTS, auth_endpoint=auth_endpoint_GTS, session=session_GTS)

    for key in allerts_list:
        print('name:', key['name'])
        print('query:',key['query'])
        print('sevirity:',key['sevirity'])
        print("Adding new alert")
        add_alert_rule(
            alert_name=key['name'],
            search_query=key['query'],
            cron_schedule="* * * * *",  # Run every minute
            alert_type="number of events",
            alert_threshold="0",  # Trigger alert if more than 0 events occur
            alert_expires="60d",
            alert_severity=key["sevirity"]
        )
        time.sleep(0.3)
        print('-'*50)
        
def main():
    #-------------------------PART TO EXPORT--------------------------
    isOk = export_rules()
    print("Successfully exported:", isOk)

    #-------------------------PART TO IMPORT-----------------------------
    # isOk = import_rules()
    # print("Successful imported:", isOk)

if __name__ == "__main__":
    main()
