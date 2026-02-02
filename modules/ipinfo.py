import os
import requests
from modules.logger import log

IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')
BASE_URL = "https://ipinfo.io"

def check_ip(ip_address: str) -> dict:
    # Handle IPinfo.io Geolocation/ASN check.
    log(f"IPinfo: Starting Geo/ASN analysis for {ip_address}.", 'DEBUG')
    
    if not IPINFO_API_KEY:
        log("IPinfo: API key missing (optional). Skipping call.", 'WARNING')
        return {"source": "IPinfo", "status": "Skipped", "data": "API Key Missing"}

    url = f"{BASE_URL}/{ip_address}/json"
    params = {"token": IPINFO_API_KEY}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()
        
        # IPinfo is used for geolocation/ASN, so the raw score is set to 0.
        raw_score = 0 
        
        log(f"IPinfo: Successfully retrieved data (Geo/ASN). Country: {data.get('country')}", 'DEBUG')
        
        return {
            "source": "IPinfo",
            "status": "Success",
            "raw_score": raw_score, 
            "data": data # All Geodata.
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"IPinfo: HTTP error {e.response.status_code} during call for {ip_address}.", 'ERROR')
        return {"source": "IPinfo", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"IPinfo: Connection error: {e}", 'ERROR')
        return {"source": "IPinfo", "status": "Connection Error", "data": None}