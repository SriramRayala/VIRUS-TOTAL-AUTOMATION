import argparse
import time
import requests
import pandas as pd
import json
import base64
import os
import hashlib

API_KEY = "d803ce098bcaa3286b849de7adea4f1ca086cff3ce5ef7cde537d8462dab69a7"

parser = argparse.ArgumentParser(description="Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam")
parser.add_argument("-s", "--single-entry", help="ip or url for analysis")
parser.add_argument("-V", "--version", help="show program version", action="store_true")
args = parser.parse_args()

def url_report(arg):
    target_url = arg
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"Accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    decoded_response = response.json()
    
    # Check if 'data' key exists in the response
    if 'data' in decoded_response:
        return decoded_response
    else:
        print("Error: 'data' key not found in response")
        return None

if args.single_entry:
    response = url_report(args.single_entry)
    if response is not None:
        print(json.dumps(response, indent=4))
elif args.version:
    print("VT API v3 IP address and URL analysis 2.0")
else:
    print("usage: vt-ip-url-analysis.py [-h] [-s SINGLE_ENTRY] [-V]")

