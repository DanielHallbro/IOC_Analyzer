import json
import os
from datetime import datetime, timedelta

from modules.logger import log

CACHE_FILE = "ioc_cache.json"
CACHE_EXPIRY_DAYS = 1 # IOCs are cached for 1 day. Can be adjusted if needed.

def load_cache() -> dict:
    # Loads existing cache from disk. Returns an empty dictionary if the file is missing/corrupt.
    if not os.path.exists(CACHE_FILE):
        return {}
        
    try:
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        log(f"Cache: Warning! {CACHE_FILE} is corrupt and will be recreated.", 'WARNING')
        return {}
    except Exception as e:
        log(f"Cache: An unexpected error occurred during loading: {e}", 'ERROR')
        return {}

# Cache data is loaded and stored globally for performance
IOC_CACHE = load_cache()

def save_cache():
    # Saves cache data to disk.
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(IOC_CACHE, f, indent=4)
    except Exception as e:
        log(f"Cache: Could not save cache file: {e}", 'ERROR')


def check_cache(ioc: str) -> list | None:
    # Checks if an IOC exists in the cache and is valid. Returns result if valid.
    if ioc not in IOC_CACHE:
        log(f"Cache: No result for {ioc}.", 'DEBUG')
        return None

    entry = IOC_CACHE[ioc]
    cache_time = datetime.fromisoformat(entry['timestamp'])

    # Check expiry date
    if datetime.now() > cache_time + timedelta(days=CACHE_EXPIRY_DAYS):
        log(f"Cache: No result for {ioc}. The result has expired.", 'INFO')
        del IOC_CACHE[ioc] # Remove invalid entry
        return None

    log(f"Cache: Result found for {ioc}. Using cached result.", 'INFO')
    return entry['results']

def update_cache(ioc: str, api_results: list):
    # Saves a new API result to the cache and saves the file.
    IOC_CACHE[ioc] = {
        "timestamp": datetime.now().isoformat(),
        "results": api_results
    }
    save_cache()