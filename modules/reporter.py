import os
from modules.logger import log

def generate_report(output_filename: str, report_content: str):
    # Writes the formatted analysis report to a specified file in append mode.
    if not output_filename:
        log("Reporter: No filename specified for report. Aborting.", 'DEBUG')
        return

    try:
        # Using 'a' (Append) to handle multiple analyses correctly
        with open(output_filename, 'a', encoding='utf-8') as f: 
            
            # Adding a clear separator
            f.write("\n\n" + "="*20 + f" ANALYSIS STARTED: {os.path.basename(output_filename)} " + "="*20 + "\n\n")
            f.write(report_content)
            
        log(f"Reporter: Analysis report successfully added to: {output_filename}", 'DEBUG')
        print(f"\n[REPORT] Analysis result added to: {output_filename}")

    except Exception as e:
        log(f"Reporter: Could not write report to {output_filename}. Error: {e}", 'ERROR')
        print(f"\n[ERROR] Could not write report to file: {output_filename}")