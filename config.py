"""
Configuration settings for the Intrusion Detection System.
"""

# Network monitoring settings
INTERFACE = "en0"  # Network interface to monitor (change to your interface)
PACKET_COUNT = 100  # Number of packets to capture in each monitoring cycle
SUSPICIOUS_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 8080]  # Ports to monitor
PORT_SCAN_THRESHOLD = 5  # Number of different ports accessed in short time to trigger alert

# System monitoring settings
CPU_THRESHOLD = 90  # CPU usage percentage threshold
MEMORY_THRESHOLD = 90  # Memory usage percentage threshold
DISK_THRESHOLD = 90  # Disk usage percentage threshold

# Log monitoring settings
LOG_FILES = [
    "/var/log/system.log",  # macOS/Linux system log
    "/var/log/auth.log",    # Authentication log (Linux)
]
LOG_PATTERNS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "connection closed",
    "refused connect",
    "error",
    "warning",
    "denied",
    "violation",
]

# Alert settings
ALERT_LOG_FILE = "ids_alerts.log"
EMAIL_ALERTS = False
EMAIL_SETTINGS = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your_email@gmail.com",
    "receiver_email": "your_email@gmail.com",
    "password": "your_app_password"  # Use app password for Gmail
}

# General settings
DEBUG_MODE = True  # Enable/disable debug messages
SCAN_INTERVAL = 60  # Time in seconds between scans 