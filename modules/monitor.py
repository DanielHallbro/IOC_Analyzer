import os
import time
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from modules.logger import log
from modules.utils import calculate_file_sha256

class IOCWatchHandler(FileSystemEventHandler):
   
    # Handles file system events in the watch folder.
    # Processes .txt files as lists of IOCs and other files as binaries to be hashed.

    def __init__(self, process_func, report_dir, watch_path):
        self.process_func = process_func
        self.report_dir = report_dir
        self.watch_path = watch_path

    def on_created(self, event):
        # Triggered when a new file is added to the watched directory.
        if event.is_directory:
            return
        
        file_path = event.src_path
        file_name = os.path.basename(file_path)

        # Ignore files created inside our own subdirectories to prevent loops
        if any(x in file_path for x in ["processed", "reports"]):
            return

        # Visual separation for readability in logs and console
        print("\n" + "-"*40)
        log(f"Monitor: New file detected: {file_name}", 'INFO')
        
        # Give the OS a moment to finish writing the file to disk
        time.sleep(1)

        # Generate a unique report name with a timestamp
        timestamp = time.strftime("%Y%m%d-%H%M")
        report_file = os.path.join(self.report_dir, f"Report_{file_name}_{timestamp}.txt")

        # Write the professional header to the new report file
        self._write_report_header(report_file, file_name)

        # Determine processing logic based on file extension
        if file_name.lower().endswith('.txt'):
            self._handle_text_file(file_path, report_file)
        else:
            self._handle_binary_file(file_path, report_file)

        # Clean up by moving the original file to the processed folder
        self._move_to_processed(file_path)

    def _write_report_header(self, report_path, original_name):
        """Creates a standardized header for the individual analysis report."""
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write(f"IOC MONITORING REPORT - AUTOMATED ANALYSIS\n")
            f.write(f"Source File:   {original_name}\n")
            f.write(f"Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")

    def _write_report_footer(self, report_path):
        """Writes a closing footer to the report to signal completion."""
        with open(report_path, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*60 + "\n")
            f.write(f"ANALYSIS COMPLETED AT: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("Status: All identified IOCs processed.\n")
            f.write("="*60 + "\n")

    def _handle_text_file(self, source_path, report_path):
        """Reads a text file line by line and treats each line as an IOC."""
        log(f"Monitor: Extracting IOCs from text file: {source_path}", 'DEBUG')
        with open(source_path, 'r', encoding='utf-8') as f:
            for line in f:
                ioc = line.strip()
                if ioc:
                    # Calls the main analysis function passed during initialization
                    self.process_func(ioc, report_path)

        # Add the footer once the loop through the file is done
        self._write_report_footer(report_path)

    def _handle_binary_file(self, source_path, report_path):
        """Calculates SHA-256 hash for binary files and sends the hash for analysis."""
        file_hash = calculate_file_sha256(source_path)
        log(f"Monitor: Binary file hashed: {file_hash}", 'INFO')
        
        with open(report_path, 'a', encoding='utf-8') as f:
            f.write(f"Target Identification:\n")
            f.write(f"Computed SHA-256 Hash: {file_hash}\n")
            f.write("-" * 30 + "\n\n")
            
        self.process_func(file_hash, report_path)
        # Add the footer once the loop through the file is done
        self._write_report_footer(report_path)

    def _move_to_processed(self, source_path):
        """Moves the analyzed file to a 'processed' subfolder to keep the workspace clean."""
        processed_dir = os.path.join(self.watch_path, "processed")
        if not os.path.exists(processed_dir):
            os.makedirs(processed_dir)
        
        dest_path = os.path.join(processed_dir, os.path.basename(source_path))
        
        try:
            # Using shutil.move for cross-filesystem compatibility
            shutil.move(source_path, dest_path)
            log(f"Monitor: File successfully moved to processed folder.", 'INFO')
        except Exception as e:
            log(f"Monitor: Error moving file: {e}", 'ERROR')

def start_monitoring(watch_path, process_func):
    """Initializes and starts the folder observer."""
    report_dir = os.path.join(watch_path, "reports")
    
    # Ensure necessary directory structure exists
    for folder in [watch_path, report_dir]:
        if not os.path.exists(folder):
            os.makedirs(folder)

    event_handler = IOCWatchHandler(process_func, report_dir, watch_path)
    observer = Observer()
    observer.schedule(event_handler, watch_path, recursive=False)
    
    log(f"Monitor: Starting folder observer on {watch_path}", 'INFO')
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Monitor: Keyboard interrupt received. Stopping observer...", 'INFO')
        observer.stop()
    
    observer.join()