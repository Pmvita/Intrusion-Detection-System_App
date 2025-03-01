"""
Utility functions for the Intrusion Detection System.
"""

import os
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from colorama import Fore, Style, init
import config

# Initialize colorama
init(autoreset=True)

# Set up logging
logging.basicConfig(
    filename=config.ALERT_LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

console_logger = logging.getLogger('console')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
console_logger.addHandler(console_handler)
console_logger.propagate = False

def log_alert(alert_type, message, severity="INFO"):
    """
    Log an alert to both file and console.
    
    Args:
        alert_type (str): Type of alert (e.g., "NETWORK", "SYSTEM", "LOG")
        message (str): Alert message
        severity (str): Alert severity (INFO, WARNING, CRITICAL)
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alert_message = f"[{alert_type}] {message}"
    
    # Log to file
    if severity == "WARNING":
        logging.warning(alert_message)
    elif severity == "CRITICAL":
        logging.critical(alert_message)
    else:
        logging.info(alert_message)
    
    # Log to console with colors
    if severity == "WARNING":
        print(f"{timestamp} - {Fore.YELLOW}WARNING - {alert_message}{Style.RESET_ALL}")
    elif severity == "CRITICAL":
        print(f"{timestamp} - {Fore.RED}CRITICAL - {alert_message}{Style.RESET_ALL}")
    else:
        print(f"{timestamp} - {Fore.GREEN}INFO - {alert_message}{Style.RESET_ALL}")
    
    # Send email alert if configured
    if config.EMAIL_ALERTS and severity in ["WARNING", "CRITICAL"]:
        send_email_alert(alert_type, message, severity)

def send_email_alert(alert_type, message, severity):
    """
    Send an email alert.
    
    Args:
        alert_type (str): Type of alert
        message (str): Alert message
        severity (str): Alert severity
    """
    try:
        msg = MIMEMultipart()
        msg['From'] = config.EMAIL_SETTINGS['sender_email']
        msg['To'] = config.EMAIL_SETTINGS['receiver_email']
        msg['Subject'] = f"IDS Alert: {severity} {alert_type}"
        
        body = f"""
        Intrusion Detection System Alert
        -------------------------------
        Type: {alert_type}
        Severity: {severity}
        Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
        
        Message:
        {message}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(config.EMAIL_SETTINGS['smtp_server'], config.EMAIL_SETTINGS['smtp_port'])
        server.starttls()
        server.login(config.EMAIL_SETTINGS['sender_email'], config.EMAIL_SETTINGS['password'])
        server.send_message(msg)
        server.quit()
        
        logging.info(f"Email alert sent to {config.EMAIL_SETTINGS['receiver_email']}")
    except Exception as e:
        logging.error(f"Failed to send email alert: {str(e)}")

def debug_print(message):
    """
    Print debug messages if debug mode is enabled.
    
    Args:
        message (str): Debug message
    """
    if config.DEBUG_MODE:
        print(f"{Fore.CYAN}[DEBUG] {message}{Style.RESET_ALL}") 