import requests
import sys

# Define your VirusTotal API key
API_KEY = "YOUR_API_KEY"

# URL for the VirusTotal API endpoint to submit files
UPLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

# Define the VirusTotal API endpoint for retrieving scan reports
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

def scan_file(file_path):
    # Create a dictionary with the API key as a parameter
    params = {'apikey': API_KEY}

    # Use a 'multipart/form-data' POST request to upload the file
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(UPLOAD_URL, files=files, params=params)

    # Check the HTTP status code of the response
    if response.status_code == 200:
        # Request was successful
        json_response = response.json()
        # Print the JSON response from VirusTotal
        print(json_response)
        # Get the scan ID from the JSON response
        scan_id = json_response['scan_id']
        check_scan_result(scan_id)
    else:
        # Request was not successful
        print(f"Error: {response.status_code}")

def check_scan_result(scan_id):
    # Create a new dictionary of parameters
    report_params = {'apikey': API_KEY, 'resource': scan_id}

    # Send a GET request to retrieve the scan report
    report_response = requests.get(REPORT_URL, params=report_params)

    # Check the HTTP status code of the response
    if report_response.status_code == 200:
        # Request was successful
        report_json = report_response.json()
        # Print the scan report
        print(report_json)
    else:
        # Request was not successful
        print(f"Error: {report_response.status_code}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
    else:
        file_path = sys.argv[1]
        scan_file(file_path)