"""
Network monitoring module for the Intrusion Detection System.
Monitors network traffic for suspicious activities.
"""

import time
import socket
import threading
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP
import config
from utils import log_alert, debug_print

# Store connection attempts for port scan detection
connection_attempts = defaultdict(list)
# Store packet statistics
packet_stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
    "suspicious": 0
}

def analyze_packet(packet):
    """
    Analyze a network packet for suspicious activity.
    
    Args:
        packet: Scapy packet object
    """
    global packet_stats
    
    # Update packet statistics
    packet_stats["total"] += 1
    
    # Check if packet has IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Analyze TCP packets
        if TCP in packet:
            packet_stats["tcp"] += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check for suspicious ports
            if dst_port in config.SUSPICIOUS_PORTS:
                packet_stats["suspicious"] += 1
                debug_print(f"Suspicious TCP connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
                # Record connection attempt for port scan detection
                timestamp = time.time()
                connection_attempts[src_ip].append((timestamp, dst_port))
                
                # Check for port scanning
                check_port_scan(src_ip)
            
            # Check for SYN flood (lots of SYN packets)
            if packet[TCP].flags == 2:  # SYN flag
                # This is simplified; a real IDS would track SYN rates over time
                pass
        
        # Analyze UDP packets
        elif UDP in packet:
            packet_stats["udp"] += 1
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Check for suspicious ports
            if dst_port in config.SUSPICIOUS_PORTS:
                packet_stats["suspicious"] += 1
                debug_print(f"Suspicious UDP connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Count other packet types
        else:
            if packet.haslayer("ICMP"):
                packet_stats["icmp"] += 1
                # Check for ICMP flood (simplified)
                pass
            else:
                packet_stats["other"] += 1

def check_port_scan(src_ip):
    """
    Check if an IP is performing a port scan.
    
    Args:
        src_ip (str): Source IP address to check
    """
    global connection_attempts
    
    # Get recent connection attempts (last 60 seconds)
    current_time = time.time()
    recent_attempts = [attempt for attempt in connection_attempts[src_ip] 
                      if current_time - attempt[0] < 60]
    
    # Update the list with only recent attempts
    connection_attempts[src_ip] = recent_attempts
    
    # Count unique destination ports
    unique_ports = set(port for _, port in recent_attempts)
    
    # If number of unique ports exceeds threshold, alert port scan
    if len(unique_ports) >= config.PORT_SCAN_THRESHOLD:
        ports_str = ", ".join(str(port) for port in unique_ports)
        log_alert(
            "NETWORK", 
            f"Possible port scan detected from {src_ip}. Ports: {ports_str}",
            "WARNING"
        )
        # Reset the attempts for this IP to avoid repeated alerts
        connection_attempts[src_ip] = []

def print_stats():
    """Print packet statistics periodically."""
    while True:
        debug_print(f"Packet Statistics: {packet_stats}")
        time.sleep(10)

def start_monitoring():
    """Start network monitoring."""
    log_alert("NETWORK", "Starting network monitoring...", "INFO")
    
    # Start statistics thread
    stats_thread = threading.Thread(target=print_stats, daemon=True)
    stats_thread.start()
    
    try:
        # Start packet sniffing
        sniff(
            iface=config.INTERFACE,
            prn=analyze_packet,
            count=config.PACKET_COUNT,
            store=0
        )
    except Exception as e:
        log_alert("NETWORK", f"Error in network monitoring: {str(e)}", "CRITICAL")

if __name__ == "__main__":
    start_monitoring() 