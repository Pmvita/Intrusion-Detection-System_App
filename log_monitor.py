"""
Log monitoring module for the Intrusion Detection System.
Monitors system logs for suspicious activities.
"""

import os
import time
import re
import threading
from collections import defaultdict
import config
from utils import log_alert, debug_print

# Store log file positions
file_positions = {}
# Store suspicious log entries by pattern
suspicious_entries = defaultdict(int)

def initialize_file_positions():
    """Initialize file positions for all log files."""
    for log_file in config.LOG_FILES:
        if os.path.exists(log_file):
            try:
                # Get current file size
                file_size = os.path.getsize(log_file)
                # Start reading from the end of the file
                file_positions[log_file] = file_size
                debug_print(f"Initialized log file: {log_file}, position: {file_size}")
            except Exception as e:
                log_alert("LOG", f"Error initializing log file {log_file}: {str(e)}", "WARNING")
        else:
            log_alert("LOG", f"Log file not found: {log_file}", "WARNING")

def check_log_file(log_file):
    """
    Check a log file for new entries.
    
    Args:
        log_file (str): Path to log file
    """
    try:
        # Skip if file doesn't exist
        if not os.path.exists(log_file):
            return
        
        # Get current file size
        current_size = os.path.getsize(log_file)
        last_position = file_positions.get(log_file, 0)
        
        # Check if file has been rotated (size decreased)
        if current_size < last_position:
            debug_print(f"Log file rotated: {log_file}")
            last_position = 0
        
        # Check if file has new content
        if current_size > last_position:
            with open(log_file, 'r') as f:
                # Seek to last position
                f.seek(last_position)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update file position
                file_positions[log_file] = f.tell()
                
                # Process new lines
                for line in new_lines:
                    process_log_line(log_file, line)
    
    except Exception as e:
        log_alert("LOG", f"Error checking log file {log_file}: {str(e)}", "WARNING")

def process_log_line(log_file, line):
    """
    Process a log line for suspicious patterns.
    
    Args:
        log_file (str): Source log file
        line (str): Log line to process
    """
    # Check for suspicious patterns
    for pattern in config.LOG_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            # Increment count for this pattern
            suspicious_entries[pattern] += 1
            
            # Log the suspicious entry
            log_name = os.path.basename(log_file)
            debug_print(f"Suspicious log entry in {log_name}: {line.strip()}")
            
            # Alert if pattern appears frequently
            if suspicious_entries[pattern] >= 5:
                log_alert(
                    "LOG", 
                    f"Frequent '{pattern}' entries detected in {log_name} ({suspicious_entries[pattern]} occurrences)",
                    "WARNING"
                )
                # Reset counter to avoid repeated alerts
                suspicious_entries[pattern] = 0
            break

def monitor_logs():
    """Monitor log files for suspicious activities."""
    while True:
        for log_file in config.LOG_FILES:
            check_log_file(log_file)
        
        # Sleep before next check
        time.sleep(5)

def start_monitoring():
    """Start log monitoring."""
    log_alert("LOG", "Starting log monitoring...", "INFO")
    
    # Initialize file positions
    initialize_file_positions()
    
    try:
        # Start monitoring
        monitor_logs()
    except Exception as e:
        log_alert("LOG", f"Error in log monitoring: {str(e)}", "CRITICAL")

if __name__ == "__main__":
    start_monitoring() 