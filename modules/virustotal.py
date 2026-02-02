import os
import requests
from modules.logger import log
import base64 # Needed for URL encoding. Explained further in function 'def check_url_or_hash'.

VT_API_KEY = os.getenv('VT_API_KEY') # Get API key from environment variable. Can be changed to direct input if prefered.
BASE_URL = "https://www.virustotal.com/api/v3"

def check_ip(ioc: str) -> dict:
    # Handles VirusTotal IP check.
    log(f"VT: Starting IP analysis for {ioc}.", 'DEBUG')

    # Pre flight check should catch this before.
    if not VT_API_KEY:
        log("VT: API key missing (should be caught by pre-checks). Aborting call.", 'ERROR')
        return {"source": "VirusTotal", "status": "Error", "data": "API Key Missing"}

    url = f"{BASE_URL}/ip_addresses/{ioc}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Raises exception for 4xx/5xx responses

        data = response.json().get('data', {})
        attributes = data.get('attributes', {})
        
        # Fetch relevant information
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        malicious = last_analysis_stats.get('malicious', 0)

        # Risk score: Raw data is the count of "malicious" reports.
        raw_score = malicious

        log(f"VirusTotal: Successfully fetched data for {ioc}. Malicious count: {raw_score}", 'DEBUG')

        return {
            "source": "VirusTotal",
            "status": "Success",
            "raw_score": raw_score, 
            "data": attributes
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"VT: HTTP error {e.response.status_code} during call for {ioc}.", 'ERROR')
        return {"source": "VirusTotal", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"VT: Connection error: {e}", 'ERROR')
        return {"source": "VirusTotal", "status": "Connection Error", "data": None}


def check_url_or_hash(ioc: str, ioc_type: str) -> dict:
    # Handles VirusTotal URL or Hash check.
    log(f"VT: Starting {ioc_type} analysis for {ioc}.", 'DEBUG')

    ioc_type = ioc_type.upper() # Make sure type is uppercase for consistency.

    # Decides endpoint and type
    if ioc_type == 'HASH':
        # För hashar används /files/
        endpoint = f"{BASE_URL}/files/{ioc}"
    else:
        # För URL:er måste de Base64-kodas enligt VT:s krav
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        endpoint = f"{BASE_URL}/urls/{url_id}"

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }
    
    ioc_type_friendly = "Hash" if ioc_type == 'HASH' else "URL"

    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        
        if response.status_code == 404:
            log(f"VT: Could not find a report for {ioc}.", 'INFO')
            return {"source": "VirusTotal (Other)", "status": "Not Found", "ioc_type": ioc_type_friendly, "data": None}
            
        response.raise_for_status() 

        # Fetch relevant information
        data = response.json().get('data', {})
        attributes = data.get('attributes', {})
        
        # Risk score: Raw data is the count of "malicious" reports.
        analysis_stats = attributes.get('last_analysis_stats', {})
        malicious = analysis_stats.get('malicious', 0)
        
        log(f"VT: Successfully fetched data. Malicious count: {malicious}", 'DEBUG')
        return {
            "source": "VirusTotal (Other)",
            "status": "Success",
            "raw_score": malicious,
            "ioc_type": ioc_type_friendly,
            "data": attributes
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"VT: HTTP error {e.response.status_code} during call.", 'ERROR')
        return {"source": "VirusTotal (Other)", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"VT: Connection error: {e}", 'ERROR')
        return {"source": "VirusTotal (Other)", "status": "Connection Error", "data": None}