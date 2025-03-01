"""
Port scanner module for the Intrusion Detection System.
Detects port scanning attempts on the local system.
"""

import time
import threading
import socket
import nmap
from collections import defaultdict
import config
from utils import log_alert, debug_print

# Store connection attempts
connection_history = defaultdict(list)
# Blacklisted IPs (temporary)
blacklisted_ips = set()

def scan_for_open_ports():
    """
    Scan for open ports on the local system and log them.
    """
    try:
        # Get local IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Initialize nmap scanner
        scanner = nmap.PortScanner()
        
        # Scan common ports on local system
        debug_print(f"Scanning for open ports on {local_ip}...")
        scanner.scan(local_ip, '20-1000')
        
        # Log open ports
        open_ports = []
        for port in scanner[local_ip]['tcp']:
            if scanner[local_ip]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
        
        if open_ports:
            ports_str = ", ".join(str(port) for port in open_ports)
            log_alert("PORTSCAN", f"Open ports detected: {ports_str}", "INFO")
            debug_print(f"Open ports: {ports_str}")
        else:
            debug_print("No open ports detected.")
    
    except Exception as e:
        log_alert("PORTSCAN", f"Error scanning for open ports: {str(e)}", "WARNING")

def monitor_connections():
    """
    Monitor incoming connections to detect port scanning.
    """
    try:
        # Create a raw socket to monitor connections
        # Note: This is a simplified approach. In a real IDS, you might use
        # netstat or other system tools to monitor connections.
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
        while True:
            # Receive packet
            packet = sock.recvfrom(65565)
            
            # Extract IP header (first 20 bytes)
            ip_header = packet[0][0:20]
            
            # Extract source IP (bytes 12-16)
            src_ip = socket.inet_ntoa(ip_header[12:16])
            
            # Record connection attempt
            timestamp = time.time()
            connection_history[src_ip].append(timestamp)
            
            # Check for port scanning
            check_port_scan_attempts(src_ip)
            
            # Clean up old connection history
            cleanup_connection_history()
            
    except Exception as e:
        log_alert("PORTSCAN", f"Error monitoring connections: {str(e)}", "WARNING")

def check_port_scan_attempts(ip):
    """
    Check if an IP is attempting to port scan.
    
    Args:
        ip (str): IP address to check
    """
    # Skip if already blacklisted
    if ip in blacklisted_ips:
        return
    
    # Get recent connection attempts (last 60 seconds)
    current_time = time.time()
    recent_attempts = [t for t in connection_history[ip] if current_time - t < 60]
    
    # If number of connection attempts exceeds threshold, alert port scan
    if len(recent_attempts) >= config.PORT_SCAN_THRESHOLD:
        log_alert(
            "PORTSCAN", 
            f"Port scan detected from {ip} ({len(recent_attempts)} connection attempts in 60s)",
            "WARNING"
        )
        # Add to blacklist temporarily
        blacklisted_ips.add(ip)
        # Schedule removal from blacklist after 10 minutes
        threading.Timer(600, lambda: blacklisted_ips.remove(ip)).start()

def cleanup_connection_history():
    """Clean up old connection history entries."""
    current_time = time.time()
    for ip in list(connection_history.keys()):
        # Keep only connections from the last 5 minutes
        connection_history[ip] = [t for t in connection_history[ip] if current_time - t < 300]
        # Remove empty entries
        if not connection_history[ip]:
            del connection_history[ip]

def start_monitoring():
    """Start port scan monitoring."""
    log_alert("PORTSCAN", "Starting port scan detection...", "INFO")
    
    # Scan for open ports initially
    scan_for_open_ports()
    
    # Schedule periodic port scans
    def schedule_port_scan():
        while True:
            time.sleep(300)  # Scan every 5 minutes
            scan_for_open_ports()
    
    # Start port scan thread
    scan_thread = threading.Thread(target=schedule_port_scan, daemon=True)
    scan_thread.start()
    
    # Start connection monitoring
    try:
        monitor_connections()
    except Exception as e:
        log_alert("PORTSCAN", f"Error in port scan monitoring: {str(e)}", "CRITICAL")

if __name__ == "__main__":
    start_monitoring() 