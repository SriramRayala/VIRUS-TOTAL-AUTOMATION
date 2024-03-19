import argparse
import time
import requests
import re
import pandas as pd
import json
import base64
import hashlib
import os

# Predefined API key
API_KEY = "d803ce098bcaa3286b849de7adea4f1ca086cff3ce5ef7cde537d8462dab69a7"

# Initialize the argument parser
parser = argparse.ArgumentParser(description="Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam")
parser.add_argument("-s", "--single-entry", help="ip or url for analysis")
parser.add_argument("-i", "--ip-list", help="bulk ip address analysis")
parser.add_argument("-u", "--url-list", help="bulk url analysis")
parser.add_argument("-V", "--version", help="show program version", action="store_true")

# Function to generate URL report
def urlReport(arg):
    target_url = arg
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"Accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    decodedResponse = json.loads(response.text)
    return decodedResponse

# Function to handle importing a user-defined list of URLs
def urlReportLst(arg):
    with open(arg) as fcontent:
        fstring = fcontent.readlines()
    pattern = re.compile(r'(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?')
    lst = []
    for line in fstring:
        lst.append(pattern.search(line)[0])
    html_table_array = []
    for i in lst:
        result = urlReport(i)
        html_table_array.append(result)
    return html_table_array

# Function to handle importing a user-defined list of IPs
def urlReportIPLst(arg):
    with open(arg) as fh:
        string = fh.readlines()
    pattern = re.compile(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
    valid2 = []
    for line in string:
        line = line.rstrip()
        result = pattern.search(line)
        if result:
            valid2.append(line)
    html_table_array = []
    for i in valid2:
        result = urlReport(i)
        html_table_array.append(result)
    return html_table_array

# Parse command-line arguments
args = parser.parse_args()

# Check for --single-entry or -s
if args.single_entry:
    result = urlReport(args.single_entry)
    print(json.dumps(result, indent=4))
# Check for --ip-list or -i
elif args.ip_list:
    result = urlReportIPLst(args.ip_list)
    print(json.dumps(result, indent=4))
# Check for --url-list or -u
elif args.url_list:
    result = urlReportLst(args.url_list)
    print(json.dumps(result, indent=4))
# Check for --version or -V
elif args.version:
    print("VT API v3 IP address and URL analysis 2.0")
# Print usage information if no arguments are provided
else:
    print("usage: vt-ip-url-analysis.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-u URL_LIST] [-V]")

