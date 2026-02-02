#!/usr/bin/env python3

import argparse # Import for handling command-line arguments interactively and non-interactively.
from datetime import datetime # Import for timestamp in the start log.
import sys
import os # Import for environment variables.
from dotenv import load_dotenv # Import for loading .env-file with API keys.
load_dotenv() # Loads API keys from .env-file.

# Import logger, monitorying, utils, pre_checks
from modules.logger import setup_logger, log
from modules.utils import get_ioc_type # Importing utils for IOC-validation.
from modules.pre_checks import run_pre_checks # Importing pre_checks for environment checks
from modules.monitor import start_monitoring

# Import API-anrop/cache/formatter/reporter
from modules.virustotal import check_ip as check_vt_ip, check_url_or_hash as check_vt_other
from modules.abuseipdb import check_ip as check_abuse_ip
from modules.ipinfo import check_ip as check_ipinfo_ip
from modules.formatter import format_ip_analysis, format_other_analysis
from modules.cache import check_cache, update_cache, save_cache # Importing cache-modulen (FB1).
from modules.reporter import generate_report # Importing reporter-modulen (FB2).

VERSION = "2.0.0" 
DEVELOPER = "Daniel Hållbro (Student)"
LOG_FILE_PATH = "ioc_analyzer.log" # Log file name.


def analyze_ioc(ioc,report_filename=None):
    # Analyzes an IOC (IP, URL/Domain) using various APIs.
    log(f"--- Analysis started for: {ioc} ---", 'DEBUG') 

    ioc = ioc.strip().lower()  # Clean whitespace and make lowercase for VirusTotal Hash consistency.

    # Strict type determination
    ioc_type = get_ioc_type(ioc)

    if ioc_type is None:
        # If utils.py validation fails.
        log(f"Validation failed for input: {ioc}", 'WARNING')
        print(f"\n[ERROR] '{ioc}' is not a valid format.")
        print("-> Allowed formats: IPv4, Domain/URL, or Hash (MD5/SHA1/SHA256).")
        return # Exit the function if invalid IOC

    cached_data = check_cache(ioc)
    if cached_data:
        log(f"Using cached data for presentation.", 'DEBUG')
                
        if ioc_type == 'IP':
            formatted_output = format_ip_analysis(cached_data, ioc)
        else:
            # For URL/Hash, we fetch the first (and only) result in the list
            formatted_output = format_other_analysis(cached_data[0], ioc)
        if report_filename:
            generate_report(report_filename, formatted_output)
        else:
            print(formatted_output)

        log(f"Formatted analysis report (from cache):\n{formatted_output}", 'DEBUG') 
        log("Analysis completed and presented (CACHED).", 'INFO')
        return # Exit the function if cached result exists
        
    ioc_type = get_ioc_type(ioc)
    api_results = []

    if ioc_type == 'IP':
        log("IOC Type: IP address. No cached result. Using multisource IP analysis.", 'DEBUG')
        
        # Calls to all three APIs for IP analysis
        vt_result = check_vt_ip(ioc)
        abuse_result = check_abuse_ip(ioc)
        ipinfo_result = check_ipinfo_ip(ioc)

        # Collect all results
        api_results.append(vt_result)
        api_results.append(abuse_result)
        api_results.append(ipinfo_result)
        
        # Use formatter for neat output
        formatted_output = format_ip_analysis(api_results, ioc)
        if report_filename:
            generate_report(report_filename, formatted_output)
        else:
            print(formatted_output)

        update_cache(ioc, api_results) # Saves the collected result
        log(f"Saved analysis results for {ioc} to the cache.", 'DEBUG')

        log(f"Formatted analysis report:\n{formatted_output}", 'DEBUG') # Ensures that the formatted output is logged neatly.

    elif ioc_type == 'URL' or ioc_type == 'HASH':
        log(f"IOC Type: {ioc_type}. No cached result. Using VirusTotal for analysis.", 'DEBUG')

        vt_result = check_vt_other(ioc, ioc_type)
        api_results.append(vt_result)
        formatted_output = format_other_analysis(vt_result, ioc)

        if report_filename:
            generate_report(report_filename, formatted_output)
        else:
            print(formatted_output)


        update_cache(ioc, api_results) # Saves the collected result.
        log(f"Saved analysis results for {ioc} to the cache.", 'DEBUG')

        log(f"Formatted analysis report:\n{formatted_output}", 'DEBUG') # Ensures that the formatted output is logged neatly.
        
    log("Analysis completed and presented.", 'DEBUG')

def main():
    # Set up the logger at program start
    setup_logger(LOG_FILE_PATH)
    log(f"IOC Analyzer v{VERSION} started ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})", 'DEBUG')


    if not run_pre_checks(LOG_FILE_PATH):
        log("Environment checks failed. Exiting in a controlled manner.", 'CRITICAL')
        sys.exit(1) # Important: Exit the script in a controlled manner if VT is missing!

    # Argument parser for command-line arguments
    parser = argparse.ArgumentParser(
        description="IOC Analyzer Script – Automated threat analysis from VirusTotal and AbuseIPDB, and Geolocation/ASN from IPinfo.io.\n\n"
                    "Usage Examples:\n"
                    "  python3 main.py -v/--version\n"
                    "  python3 main.py -h/--help/\n"
                    "  python3 main.py -t/--target <IOC>\n"
                    "  python3 main.py -r/--report <FILNAMN>\n"
                    "  python3 main.py -m/--monitor\n"
                    "  python3 main.py -t <IOC> -r <FILNAMN>\n\n",
        formatter_class=argparse.RawTextHelpFormatter # For neater examples/description
    )    

    # Version flag -v/--version
    parser.add_argument(
        '-v', '--version', 
        action='version', 
        version=f'%(prog)s v{VERSION} by {DEVELOPER}', 
        help="Displays the script version and developer."
    )

    # Target flag -t/--target
    parser.add_argument(
        '-t', '--target', 
        type=str,
        help="-t or --target to specify an IOC (IP or URL/Hash) directly from the command line. The script runs in non-interactive mode."
    )
    
    # Report flag -r/--report
    parser.add_argument(
        '-r', '--report',
        type=str,
        help="-r or --report to specify a file to write the analysis report to (for example 'report.txt')."
    )

    # Monitor flag -m/--monitor
    parser.add_argument(
        "-m", "--monitor", 
        action="store_true", 
        help="-m or --monitor to start the watch folder monitor"
    )

    args = parser.parse_args()


    # Monitor mode
    if args.monitor:
        log("User started the script in MONITOR mode.", 'INFO')
        print("\n" + "="*50)
        print("  IOC MONITOR MODE ACTIVE")
        print("  Watching folder: ./watch_folder")
        print("  (Press Ctrl+C to stop)")
        print("="*50 + "\n")
        
        # We send watch_path and process_func to the monitor
        # We set watch_path to ./watch_folder to maintain platform independence.
        start_monitoring(watch_path="./watch_folder", process_func=analyze_ioc)
        return # Exit main() after monitor stops

    # Non-interactive mode with target flag
    if args.target:
        log(f"Starting analysis in non-interactive mode for: {args.target}", 'INFO') 
        analyze_ioc(args.target, args.report)
    else:
        # Only if no target is provided, we go into interactive mode
        print("Welcome to IOC Analyzer v" + VERSION)
    
        while True:
            try:
                raw_input = input("\nEnter IOC (IP / Domain / Hash) or 'exit': ")
                
                if raw_input.lower() == 'exit':
                    log("User chose to exit.", 'DEBUG') 
                    break

                ioc_type = get_ioc_type(raw_input)

                if ioc_type is None:
                    # Strict validation failed
                    log(f"Invalid IOC format entered: {raw_input}", 'WARNING')
                    print("[Error]: Invalid input format.")
                    print("Please enter a valid IPv4, Domain (google.com), or Hash (MD5/SHA256).")
                    continue # Jump back to input prompt

                analyze_ioc(raw_input.strip(), args.report)
                
            except KeyboardInterrupt:
                # Handling of keyboard interruption from the user e.g. Ctrl+C(Linux/macOS)
                log("User interrupted the script via keyboard interrupt.", 'DEBUG')
                print("\nAnalysis interrupted by the user. Exiting.")
                save_cache() # Saves the cache at program termination (FB1).
                break
            except Exception as e:
                # Handling of unexpected errors
                log(f"An unexpected error occurred in main loop: {e}", 'CRITICAL')
                print(f"\n[CRITICAL ERROR] An unexpected error occurred. Check the log file ({LOG_FILE_PATH}).")
                break


    log("Script exited in a controlled manner.", 'DEBUG')

    save_cache() # Saves the cache at program termination (FB1).
if __name__ == "__main__":
    main()