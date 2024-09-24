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

# Set data_view_id if custom
data_view_id = "logs-*" # Default value is logs-*

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
        
def import_kibana_rules(kibana_url, session, export_filepath, username, password):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    
    with open("rules_export.json", "r") as file:
        rules_list = json.loads(file.read())
    
    print(f"Rules List Length: {len(rules_list)}")
    
    success_atmpt = 0
    failed_atmpt = 0
    
    for rule in rules_list:
        #Set body
        data = rule

        # Construct the URL for retrieving alerting rules
        url = f"{kibana_url}/api/detection_engine/rules"

        # Perform the GET request to retrieve the alerting rules
        response = session.post(url, headers=headers, auth=HTTPBasicAuth(username, password), data=json.dumps(data))

        # Check the response
        if response.status_code == 200:
            print("Alert Successfully added")
            success_atmpt += 1
            
        else:
            print(f"Failed to retrieve alerts. Status Code: {response.status_code}, Response: {response.text}")
            failed_atmpt += 1
    
    print(f"Allerts added successfully: {success_atmpt}\nAllerts failed: {failed_atmpt}")
    
def import_kibana_rules_test(kibana_url, session, export_filepath, username, password):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    
    with open("rules_export.json", "r") as file:
        rules_list = json.loads(file.read())
    
    success_atmpt = 0
    failed_atmpt = 0
    
    #Set body
    data = rules_list[10]

    # Construct the URL for retrieving alerting rules
    url = f"{kibana_url}/api/detection_engine/rules"

    # Perform the GET request to retrieve the alerting rules
    response = session.post(url, headers=headers, auth=HTTPBasicAuth(username, password), data=json.dumps(data))

    # Check the response
    if response.status_code == 200:
        print("Alert Successfully added")
        success_atmpt += 1
        
    else:
        print(f"Failed to retrieve alerts. Status Code: {response.status_code}, Response: {response.text}")
        failed_atmpt += 1

def import_kibana_lolbins_rules(kibana_url, session, export_filepath, username, password):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    
    with open("data/LOLbins.json", "r") as file:
        rules_list = json.loads(file.read())
    
    print(f"Rules List Length: {len(rules_list)}")
    
    success_atmpt = 0
    failed_atmpt = 0
    
    for rule in rules_list:
        #Set body
        rule_name = f"(Windows) {rule["name"]}"
        data = {
            "type": "query",
            "filters": [],
            "language": "kuery",
            "query": f"(host.os.type: \"windows\") AND ({rule["query"]})",
            "data_view_id": data_view_id,
            "author": [],
            "false_positives": [],
            "references": [],
            "risk_score": 21,
            "risk_score_mapping": [],
            "severity": "low",
            "severity_mapping": [],
            "threat": [],
            "name": rule_name,
            "description": f"Template Description for LOLBins rule f{rule_name}",
            "tags": [],
            "setup": "",
            "license": "",
            "interval": "5m",
            "from": "now-360s",
            "to": "now",
            "meta": {
                "from": "1m",
                "kibana_siem_app_url": "http://192.168.223.178:5601/app/security"
            },
            "actions": [],
            "enabled": True
        }

        # Construct the URL for retrieving alerting rules
        url = f"{kibana_url}/api/detection_engine/rules"

        # Perform the GET request to retrieve the alerting rules
        response = session.post(url, headers=headers, auth=HTTPBasicAuth(username, password), data=json.dumps(data))

        # Check the response
        if response.status_code == 200:
            print("Alert Successfully added")
            success_atmpt += 1
        elif response.status_code == 409:
            print("WARNING! Alert with same name exists")
            counter = 1
            isSuccess = False
            while not isSuccess:
                data["name"] = rule_name + f"-{counter}"
                response = session.post(url, data=data, verify=False)
                if response.status_code == 201:
                    isSuccess = True
                    print(f"ALERT was added under the name: {data["name"]}")
                else:
                    counter += 1
        else:
            print(f"Failed to retrieve alerts. Status Code: {response.status_code}, Response: {response.text}")
            failed_atmpt += 1
    
    print(f"Allerts added successfully: {success_atmpt}\nAllerts failed: {failed_atmpt}")
    
def import_kibana_gtfobins_rules(kibana_url, session, export_filepath, username, password):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    
    with open("data/new_gtfobins.json", "r") as file:
        rules_list = json.loads(file.read())
    
    print(f"Rules List Length: {len(rules_list)}")
    
    success_atmpt = 0
    failed_atmpt = 0
    
    for rule in rules_list:
        #Set body
        rule_name = f"(Linux) {rule["name"]}"
        data = {
            "type": "query",
            "filters": [],
            "language": "kuery",
            "query": f"(host.os.type: \"linux\") AND ({rule["query"]})",
            "data_view_id": data_view_id,
            "author": [],
            "false_positives": [],
            "references": [],
            "risk_score": 21,
            "risk_score_mapping": [],
            "severity": "medium",
            "severity_mapping": [],
            "threat": [],
            "name": rule_name,
            "description": f"Template Description for GTFOBins rule f{rule_name}",
            "tags": [],
            "setup": "",
            "license": "",
            "interval": "5m",
            "from": "now-360s",
            "to": "now",
            "meta": {
                "from": "1m",
                "kibana_siem_app_url": "http://192.168.223.178:5601/app/security"
            },
            "actions": [],
            "enabled": True
        }

        # Construct the URL for retrieving alerting rules
        url = f"{kibana_url}/api/detection_engine/rules"

        # Perform the GET request to retrieve the alerting rules
        response = session.post(url, headers=headers, auth=HTTPBasicAuth(username, password), data=json.dumps(data))

        # Check the response
        if response.status_code == 200:
            print("Alert Successfully added")
            success_atmpt += 1
            
        elif response.status_code == 409:
            print("WARNING! Alert with same name exists")
            counter = 1
            isSuccess = False
            while not isSuccess:
                data["name"] = rule_name + f"-{counter}"
                response = session.post(url, data=data, verify=False)
                if response.status_code == 201:
                    isSuccess = True
                    print(f"ALERT was added under the name: {data["name"]}")
                else:
                    counter += 1
        else:
            print(f"Failed to retrieve alerts. Status Code: {response.status_code}, Response: {response.text}")
            failed_atmpt += 1
    
    print(f"Allerts added successfully: {success_atmpt}\nAllerts failed: {failed_atmpt}")
    
def execute_endpoint_command(command ,kibana_url, username, password):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    
    # Set Body
    data = {
        "endpoint_ids": ["ed518850-681a-4d60-bb98-e22640cae2a8"],
        "parameters": {
            "command": "ls -al",
            "timeout": 600
        },
        "comment": "Get list of all files"
    }
    
def get_endpoints(kibana_url, username, password):
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    
    # Construct the URL for retrieving alerting rules
    url = f"{kibana_url}/api/endpoint/metadata"

    # Perform the GET request to retrieve the alerting rules
    response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password))
    print(response.json())

# Example usage
if __name__ == "__main__":
    # Login to Kibana and create a session
    session = kibana_login(kibana_url, username, password)

    if session:
        # Retrieve and print the alerting rules
        import_filepath = "rules_export.json"  # Specify where to save the exported rules
        
        # --Working--
        import_kibana_gtfobins_rules(kibana_url, session, import_filepath, username, password)
        import_kibana_lolbins_rules(kibana_url, session, import_filepath, username, password)