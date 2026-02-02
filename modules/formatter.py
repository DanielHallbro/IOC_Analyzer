import json

def format_ip_analysis(results: list, ioc: str, is_cached = False) -> str:
    # Formats and presents raw data from VT, AbuseIPDB and IPinfo.

    cache_status = "Cached result" if is_cached else ""
    output = f"\n--- ANALYSIS RESULT FOR {ioc} - {cache_status} ---\n"
    # Uses next() to find the result based on the source
    vt_data = next((r for r in results if r['source'] == 'VirusTotal'), None)
    abuse_data = next((r for r in results if r['source'] == 'AbuseIPDB'), None)
    ipinfo_data = next((r for r in results if r['source'] == 'IPinfo'), None)

    # --- 1. VirusTotal Result ---
    output += "\n### 🦠 VirusTotal (Threat Reputation)\n"
    if vt_data and vt_data['status'] == 'Success':
        # We extract key data directly from VT
        stats = vt_data['data'].get('last_analysis_stats', {})
        total_engines = sum(stats.values()) # Total number of engines (Rough estimate)
        malicious = stats.get('malicious', 0)
        
        output += f"  > Malicious Detections: {malicious} of {total_engines}\n"
        output += f"  > Threat Reputation: {'Yes' if malicious > 0 else 'No'}\n"
        output += f"  > Report: https://www.virustotal.com/gui/ip-address/{ioc}\n"
    else:
        output += f"  > Status: {vt_data['status'] if vt_data else 'Failed'}\n"


    # --- 2. AbuseIPDB Result ---
    output += "\n### 🛡️ AbuseIPDB (Community Malicious Score)\n"
    if abuse_data and abuse_data['status'] == 'Success':
        # We extract Abuse Confidence Score
        score = abuse_data['data'].get('abuseConfidenceScore', 'N/A')
        reports = abuse_data['data'].get('totalReports', 'N/A')

        output += f"  > Abuse Score: {score}% (Scale 0-100)\n"
        output += f"  > Total Reports: {reports}\n"
        output += f"  > Latest Report: {abuse_data['data'].get('lastReportedAt', 'N/A')}\n"
    elif abuse_data and abuse_data['status'] == 'Skipped':
        output += "  > **WARNING:** Skipped. API key (ABUSE_API_KEY) missing.\n"
    else:
        output += f"  > Status: {abuse_data['status'] if abuse_data else 'Failed'}\n"


    # --- 3. IPinfo.io Result (Contextual Data) ---
    output += "\n### 📍 IPinfo.io (Geolocation & Network)\n"
    if ipinfo_data and ipinfo_data['status'] == 'Success':
        data = ipinfo_data['data']
        output += f"  > Country: {data.get('country_name', data.get('country', 'N/A'))} ({data.get('country')})\n"
        output += f"  > City/Region: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}\n"
        output += f"  > Organisation (ASN): {data.get('org', 'N/A')}\n"
        output += f"  > Hostname: {data.get('hostname', 'N/A')}\n"
    elif ipinfo_data and ipinfo_data['status'] == 'Skipped':
        output += "  > **WARNING:** Skipped. API key (IPINFO_API_KEY) missing.\n"
    else:
        output += f"  > Status: {ipinfo_data['status'] if ipinfo_data else 'Failed'}\n"

    output += "\n--- ANALYSIS COMPLETE ---\n"
    return output

def format_other_analysis(result: dict, ioc: str, is_cached = False) -> str:
    # Formats and presents analysis for URL and Hash (only VT).
    cache_status = "Cached result" if is_cached else ""
    output = f"\n--- ANALYSIS RESULT FOR {ioc} ---{cache_status}\n"
    
    ioc_type = result.get('ioc_type', 'N/A')
    
    output += f"\n### 🦠 VirusTotal ({ioc_type.upper()} Analysis)\n"
    
    if result['status'] == 'Success':
        stats = result['data'].get('last_analysis_stats', {})
        total_engines = sum(stats.values())
        malicious = stats.get('malicious', 0)
        
        output += f"  > IOC Type: **{ioc_type.upper()}**\n"
        output += f"  > Malicious Detections: **{malicious} of {total_engines}**\n"
        output += f"  > Threat Reputation: {'Yes' if malicious > 0 else 'No'}\n"
        
        # Sets the correct report URL depending on type
        if ioc_type == 'HASH':
            output += f"  > Report: https://www.virustotal.com/gui/file/{ioc}\n"
        else:            
            output += f"  > Report: https://www.virustotal.com/gui/url/{result.get('url_id', ioc)}\n"

    elif result['status'] == 'Not Found':
         output += f"  > Result: No reports found for this {ioc_type}.\n"
         
    else:
        output += f"  > Status: {result['status']}\n"
        
    output += "\n--- ANALYSIS COMPLETE ---\n"
    return output