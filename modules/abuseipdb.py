import os
import requests
from modules.logger import log

ABUSE_API_KEY = os.getenv('ABUSE_API_KEY') # Fetch API key from environment variable. Can be changed to raw key input if preferred.
BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip_address: str) -> dict:
    # Handle AbuseIPDB IP check.
    log(f"AbuseIPDB: Starting IP analysis for {ip_address}.", 'DEBUG')
    
    if not ABUSE_API_KEY:
        log("AbuseIPDB: API key missing (optional). Skipping call.", 'WARNING')
        return {"source": "AbuseIPDB", "status": "Skipped", "data": "API Key Missing"}

    url = f"{BASE_URL}?ipAddress={ip_address}&maxAgeInDays=90&verbose"
    headers = {
        "Accept": "application/json",
        "Key": ABUSE_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json().get('data', {})
        
        # Fetches Abuse Score (scale 0-100)
        abuse_score = data.get('abuseConfidenceScore', 0)
        
        log(f"AbuseIPDB: Successfully fetched data. Abuse Score: {abuse_score}", 'DEBUG')
        
        return {
            "source": "AbuseIPDB",
            "status": "Success",
            "raw_score": abuse_score, # Raw data (0-100)
            "data": data
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"AbuseIPDB: HTTP error {e.response.status_code} during call for {ip_address}.", 'ERROR')
        return {"source": "AbuseIPDB", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"AbuseIPDB: Connection error: {e}", 'ERROR')
        return {"source": "AbuseIPDB", "status": "Connection Error", "data": None}