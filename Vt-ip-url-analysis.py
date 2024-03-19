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
parser.add_argument("-i", "--ip-list", help="bulk ip address analysis")
parser.add_argument("-u", "--url-list", help="bulk url analysis")
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
        filtered_response = decoded_response["data"]["attributes"]
        
        # Rest of the code remains the same
        keys_to_remove = [
            "last_http_response_content_sha256", 
            "last_http_response_code",
            "last_analysis_results",
            "last_final_url", 
            "last_http_response_content_length", 
            "url", 
            "last_analysis_date", 
            "tags", 
            "last_submission_date", 
            "threat_names",
            "last_http_response_headers",
            "categories",
            "last_modification_date",
            "title",
            "outgoing_links",
            "first_submission_date",
            "total_votes",
            "type",
            "id",
            "links",
            "trackers",
            "last_http_response_cookies",
            "html_meta"
        ]
        
        for key in keys_to_remove:
            filtered_response.pop(key, None)
            
        df = pd.DataFrame.from_dict(filtered_response, orient="index")
        df.columns = [target_url]
        epoch_time = decoded_response["data"]["attributes"]["last_analysis_date"]
        time_formatted = time.strftime('%c', time.localtime(epoch_time))
        vt_url_report_link = f"https://www.virustotal.com/gui/url/{url_id}"
        community_score = decoded_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        total_vt_reviewers = sum(decoded_response["data"]["attributes"]["last_analysis_stats"].values())
        community_score_info = f"{community_score}/{total_vt_reviewers} : security vendors flagged this as malicious"
        df.loc['virustotal report', :] = vt_url_report_link
        df.loc['community score', :] = community_score_info
        df.loc['last_analysis_date', :] = time_formatted
        df.sort_index(inplace=True)
        return df
    else:
        print("Error: 'data' key not found in response")
        return None


def url_report_lst(arg):
    with open(arg) as f:
        lines = f.readlines()
    urls = [line.strip() for line in lines if line.strip()]
    for url in urls:
        df = url_report(url)
        if df is not None:
            print(df, "\n")

def url_report_ip_lst(arg):
    with open(arg) as f:
        lines = f.readlines()
    ips = [line.strip() for line in lines if line.strip()]
    for ip in ips:
        df = url_report(ip)
        if df is not None:
            print(df, "\n")

if args.single_entry:
    df = url_report(args.single_entry)
    if df is not None:
        print(df)
elif args.ip_list:
    url_report_ip_lst(args.ip_list)
elif args.url_list:
    url_report_lst(args.url_list)
elif args.version:
    print("VT API v3 IP address and URL analysis 2.0")
else:
    print("usage: vt-ip-url-analysis.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-u URL_LIST] [-V]")
