import logging
import sys

# Global variabel for the logger
logger = None 

def setup_logger(log_file):
    # Configure logger for both file and console
    global logger
    logger = logging.getLogger('IOC_Analyzer')
    logger.setLevel(logging.DEBUG)

    # Create formatter for log messages
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Handler for file
    try:
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except IOError as e:
        # Print an error message if the log file cannot be created
        print(f"[CRITICAL ERROR] Could not create or write to log file '{log_file}': {e}")

    # Handler for console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) # Only INFO and higher to console
    console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

def log(message, level='INFO'):
    # A wrapper function for logging with the correct level.
    global logger
    if logger is None:
        # Fallback if the logger is not initialized
        print(f"[{level}] {message}")
        return

    # Handle log levels
    if level.upper() == 'DEBUG':
        logger.debug(message)
    elif level.upper() == 'INFO':
        logger.info(message)
    elif level.upper() == 'WARNING':
        logger.warning(message)
    elif level.upper() == 'ERROR':
        logger.error(message)
    elif level.upper() == 'CRITICAL':
        logger.critical(message)
    else:
        logger.info(message)