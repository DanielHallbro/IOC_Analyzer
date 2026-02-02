# The module handles environment checks (pre-flight checks) before the main analysis begins.
import os
import sys
from modules.logger import log
import requests # Used for internet connection check.

def check_internet_connection():
    # Check internet connection status by trying to reach a reliable server.
    
    # Using https-request Google's public DNS server 
    test_url = "https://www.google.com"
    timeout = 3
    
    try:
        # Attempts to create a connection to test network status. Only HEAD request for efficiency.
        requests.head(test_url, timeout=timeout)
        log("Environment check succeeded: Internet connection is active.", 'DEBUG')
        return True
    except (requests.ConnectionError, requests.Timeout):
        # Captures connection errors
        log("Environment check failed: No internet connection or DNS problem.", 'ERROR')
        # Error messages and suggested actions
        print(f"\n[ERROR] No internet connection. The script cannot reach external APIs.")
        print("  -> Action: Check your network status.")
        return False
    except Exception as e:
        # Captures unexpected errors in the log
        log(f"Unexpected error during network check: {e}", 'ERROR')
        return False


def check_api_keys():
    
    # Check API keys.
    # Requires VirusTotal as minimum, but warns for others.
    
    vt_key = os.getenv('VT_API_KEY')
    abuse_key = os.getenv('ABUSE_API_KEY')
    ipinfo_key = os.getenv('IPINFO_API_KEY')

    # 1. Check MINIMUM REQUIREMENT (VirusTotal)
    if not vt_key:
        log("Environment check failed: MINIMUM REQUIREMENT (VT_API_KEY) missing.", 'CRITICAL')
        print(f"\n[CRITICAL ERROR] Script requires VT_API_KEY to analyze IOC.")
        print("  -> Action: Add the key to the .env file (recommended) or export it in the terminal.\n" \
        "     Format: VT_API_KEY='your_virustotal_key'")
        return False

    # 2. Warns if optional keys are missing
    missing_optional = []
    if not abuse_key:
        missing_optional.append('ABUSE_API_KEY')
    if not ipinfo_key: 
        missing_optional.append('IPINFO_API_KEY')

    if missing_optional:
        log(f"WARNING: The following OPTIONAL API keys are missing: {', '.join(missing_optional)}.", 'WARNING')
        print(f"\n[WARNING] Analysis will be missing data from: {', '.join(missing_optional)}.")
        print("  -> Script continues. Recommended to set API keys for full analysis.")
    else:
        log("Environment check succeeded: All required and optional API keys are present.", 'DEBUG')

    return True

def run_pre_checks(log_file_path):
    # Main function for environment checks.
    log("Starting Environment Checks (Pre-flight checks)...", 'DEBUG')

    if not check_internet_connection():
        print(f"  -> Script terminated. Check the log file ({log_file_path}) for details.")
        return False
        
    if not check_api_keys():
        # Terminated here only if VT_API_KEY is missing. Missing optional keys are only warned about.
        print(f"  -> Script terminated. Check the log file ({log_file_path}) for details.")
        return False

    log("All Environment Checks completed successfully.", 'DEBUG')
    return True