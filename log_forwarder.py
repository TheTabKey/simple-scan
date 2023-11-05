import requests
import json

# Define the HEC endpoint and token
splunk_url = "http://splunk.server:8088"  # Replace with your Splunk server URL
hec_token = "hec-token"  # Replace with your HEC token

# Define the path to the auth.log file
auth_log_path = "/var/log/auth.log"  # Replace with the correct path on your system

# Define the sourcetype for system logs with failed authentication
sourcetype = "auth:failed_auth"

# Read the auth.log file and filter for failed authentication events
log_data = []
with open(auth_log_path, "r") as auth_log_file:
    for line in auth_log_file:
        if "Failed password" in line:
            log_data.append(line)

# Create a dictionary with log data and sourcetype
log_event = {
    "event": "\n".join(log_data),
    "sourcetype": sourcetype,
}

# Convert the log event to JSON
payload = json.dumps(log_event)

# Set the headers for the HTTP request
headers = {
    "Authorization": f"Splunk {hec_token}",
    "Content-Type": "application/json",
}

# Send the log data to Splunk via HTTP POST request
response = requests.post(splunk_url, data=payload, headers=headers)

# Check the response status
if response.status_code == 200:
    print("Log data sent successfully to Splunk")
else:
    print(f"Failed to send log data. Status code: {response.status_code}")