import argparse
import time
import requests
import pandas as pd
import json
import base64
import hashlib

# Predefined API key
API_KEY = "d803ce098bcaa3286b849de7adea4f1ca086cff3ce5ef7cde537d8462dab69a7"

# Initialize the argument parser
parser = argparse.ArgumentParser(description="Python Automated VT API v3 IP address and URL analysis 2.0 by Group-16")
parser.add_argument("-s", "--single-entry", help="IP or URL for analysis")
parser.add_argument("-V", "--version", help="Show program version", action="store_true")

# Function to generate URL report
def urlReport(arg):
    target = arg
    target_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{target_id}"
    headers = {"Accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    decoded_response = response.json()
    return decoded_response

# Function to generate HTML report
def outputHTML(decoded_response):
    html = "<html><head><title>VirusTotal Report</title></head><body>"
    html += "<h1>VirusTotal Report</h1>"
    html += "<h2>Analysis Results:</h2>"
    html += f"<pre>{json.dumps(decoded_response, indent=4)}</pre>"
    html += "</body></html>"
    with open("report.html", "w") as file:
        file.write(html)

# Parse command-line arguments
args = parser.parse_args()

# Check for --single-entry or -s
if args.single_entry:
    result = urlReport(args.single_entry)
    outputHTML(result)
    print(json.dumps(result, indent=4))
# Check for --version or -V
elif args.version:
    print("VT API v3 IP address and URL analysis 2.0")
# Print usage information if no arguments are provided
else:
    print("Usage: vt-ip-url-analysis.py [-h] [-s SINGLE_ENTRY] [-V]")

