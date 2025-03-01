#!/usr/bin/env python3
"""
Simple Intrusion Detection System (IDS)
Main module that integrates all monitoring components.
"""

import os
import time
import threading
import argparse
import signal
import sys
from colorama import Fore, Style, init

# Import monitoring modules
import network_monitor
import port_scanner
import log_monitor
import system_monitor
import config
from utils import log_alert, debug_print

# Initialize colorama
init(autoreset=True)

# Global flag to control monitoring threads
running = True

def signal_handler(sig, frame):
    """Handle interrupt signals."""
    global running
    print(f"\n{Fore.YELLOW}[*] Shutting down IDS...{Style.RESET_ALL}")
    running = False
    time.sleep(1)
    sys.exit(0)

def print_banner():
    """Print IDS banner."""
    banner = f"""
{Fore.CYAN}
 ██▓▓█████▄   ██████ 
▓██▒▒██▀ ██▌▒██    ▒ 
▒██▒░██   █▌░ ▓██▄   
░██░░▓█▄   ▌  ▒   ██▒
░██░░▒████▓ ▒██████▒▒
░▓   ▒▒▓  ▒ ▒ ▒▓▒ ▒ ░
 ▒ ░ ░ ▒  ▒ ░ ░▒  ░ ░
 ▒ ░ ░ ░  ░ ░  ░  ░  
 ░     ░          ░  
     ░               
{Style.RESET_ALL}
{Fore.GREEN}Simple Intrusion Detection System{Style.RESET_ALL}
{Fore.YELLOW}Version 1.0{Style.RESET_ALL}
"""
    print(banner)

def start_network_monitoring():
    """Start network monitoring in a separate thread."""
    if not config.DEBUG_MODE:
        # Redirect stdout to suppress scapy output
        sys.stdout = open(os.devnull, 'w')
    
    try:
        network_thread = threading.Thread(target=network_monitor.start_monitoring)
        network_thread.daemon = True
        network_thread.start()
        log_alert("IDS", "Network monitoring started", "INFO")
        return network_thread
    except Exception as e:
        log_alert("IDS", f"Failed to start network monitoring: {str(e)}", "CRITICAL")
        return None
    finally:
        if not config.DEBUG_MODE:
            # Restore stdout
            sys.stdout = sys.__stdout__

def start_port_scan_detection():
    """Start port scan detection in a separate thread."""
    try:
        port_scan_thread = threading.Thread(target=port_scanner.start_monitoring)
        port_scan_thread.daemon = True
        port_scan_thread.start()
        log_alert("IDS", "Port scan detection started", "INFO")
        return port_scan_thread
    except Exception as e:
        log_alert("IDS", f"Failed to start port scan detection: {str(e)}", "CRITICAL")
        return None

def start_log_monitoring():
    """Start log monitoring in a separate thread."""
    try:
        log_thread = threading.Thread(target=log_monitor.start_monitoring)
        log_thread.daemon = True
        log_thread.start()
        log_alert("IDS", "Log monitoring started", "INFO")
        return log_thread
    except Exception as e:
        log_alert("IDS", f"Failed to start log monitoring: {str(e)}", "CRITICAL")
        return None

def start_system_monitoring():
    """Start system monitoring in a separate thread."""
    try:
        system_thread = threading.Thread(target=system_monitor.start_monitoring)
        system_thread.daemon = True
        system_thread.start()
        log_alert("IDS", "System monitoring started", "INFO")
        return system_thread
    except Exception as e:
        log_alert("IDS", f"Failed to start system monitoring: {str(e)}", "CRITICAL")
        return None

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Simple Intrusion Detection System')
    parser.add_argument('-n', '--network', action='store_true', help='Enable network monitoring')
    parser.add_argument('-p', '--portscan', action='store_true', help='Enable port scan detection')
    parser.add_argument('-l', '--logs', action='store_true', help='Enable log monitoring')
    parser.add_argument('-s', '--system', action='store_true', help='Enable system monitoring')
    parser.add_argument('-a', '--all', action='store_true', help='Enable all monitoring modules')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    return parser.parse_args()

def main():
    """Main function."""
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Print banner
    print_banner()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Set debug mode
    if args.debug:
        config.DEBUG_MODE = True
        debug_print("Debug mode enabled")
    
    # Start monitoring modules
    threads = []
    
    if args.all or args.network:
        network_thread = start_network_monitoring()
        if network_thread:
            threads.append(network_thread)
    
    if args.all or args.portscan:
        port_scan_thread = start_port_scan_detection()
        if port_scan_thread:
            threads.append(port_scan_thread)
    
    if args.all or args.logs:
        log_thread = start_log_monitoring()
        if log_thread:
            threads.append(log_thread)
    
    if args.all or args.system:
        system_thread = start_system_monitoring()
        if system_thread:
            threads.append(system_thread)
    
    # If no specific modules selected, start all
    if not (args.network or args.portscan or args.logs or args.system or args.all):
        log_alert("IDS", "No specific modules selected, starting all modules", "INFO")
        
        network_thread = start_network_monitoring()
        if network_thread:
            threads.append(network_thread)
        
        port_scan_thread = start_port_scan_detection()
        if port_scan_thread:
            threads.append(port_scan_thread)
        
        log_thread = start_log_monitoring()
        if log_thread:
            threads.append(log_thread)
        
        system_thread = start_system_monitoring()
        if system_thread:
            threads.append(system_thread)
    
    # Main loop
    try:
        log_alert("IDS", "Intrusion Detection System started", "INFO")
        print(f"\n{Fore.GREEN}[*] IDS is running. Press Ctrl+C to stop.{Style.RESET_ALL}\n")
        
        while running:
            time.sleep(1)
    
    except KeyboardInterrupt:
        pass
    
    finally:
        log_alert("IDS", "Intrusion Detection System stopped", "INFO")

if __name__ == "__main__":
    main() 