"""
System monitoring module for the Intrusion Detection System.
Monitors system resources for unusual behavior.
"""

import time
import threading
import psutil
import config
from utils import log_alert, debug_print

# Store historical system metrics
system_metrics_history = {
    "cpu": [],
    "memory": [],
    "disk": [],
    "network": []
}

def get_system_metrics():
    """
    Get current system metrics.
    
    Returns:
        dict: System metrics
    """
    metrics = {
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "network": {
            "bytes_sent": psutil.net_io_counters().bytes_sent,
            "bytes_recv": psutil.net_io_counters().bytes_recv
        }
    }
    return metrics

def update_metrics_history(metrics):
    """
    Update metrics history.
    
    Args:
        metrics (dict): Current system metrics
    """
    # Update CPU history
    system_metrics_history["cpu"].append(metrics["cpu"])
    if len(system_metrics_history["cpu"]) > 10:
        system_metrics_history["cpu"].pop(0)
    
    # Update memory history
    system_metrics_history["memory"].append(metrics["memory"])
    if len(system_metrics_history["memory"]) > 10:
        system_metrics_history["memory"].pop(0)
    
    # Update disk history
    system_metrics_history["disk"].append(metrics["disk"])
    if len(system_metrics_history["disk"]) > 10:
        system_metrics_history["disk"].pop(0)
    
    # Update network history
    system_metrics_history["network"].append(metrics["network"])
    if len(system_metrics_history["network"]) > 10:
        system_metrics_history["network"].pop(0)

def check_cpu_usage(cpu_percent):
    """
    Check CPU usage for anomalies.
    
    Args:
        cpu_percent (float): Current CPU usage percentage
    """
    if cpu_percent > config.CPU_THRESHOLD:
        log_alert(
            "SYSTEM", 
            f"High CPU usage detected: {cpu_percent}%",
            "WARNING"
        )
    
    # Check for sudden spikes
    if len(system_metrics_history["cpu"]) >= 3:
        avg_previous = sum(system_metrics_history["cpu"][-3:-1]) / 2
        if cpu_percent > avg_previous * 2 and cpu_percent > 50:
            log_alert(
                "SYSTEM", 
                f"Sudden CPU spike detected: {cpu_percent}% (previous avg: {avg_previous:.1f}%)",
                "WARNING"
            )

def check_memory_usage(memory_percent):
    """
    Check memory usage for anomalies.
    
    Args:
        memory_percent (float): Current memory usage percentage
    """
    if memory_percent > config.MEMORY_THRESHOLD:
        log_alert(
            "SYSTEM", 
            f"High memory usage detected: {memory_percent}%",
            "WARNING"
        )
    
    # Check for sudden spikes
    if len(system_metrics_history["memory"]) >= 3:
        avg_previous = sum(system_metrics_history["memory"][-3:-1]) / 2
        if memory_percent > avg_previous * 1.5 and memory_percent > 75:
            log_alert(
                "SYSTEM", 
                f"Sudden memory spike detected: {memory_percent}% (previous avg: {avg_previous:.1f}%)",
                "WARNING"
            )

def check_disk_usage(disk_percent):
    """
    Check disk usage for anomalies.
    
    Args:
        disk_percent (float): Current disk usage percentage
    """
    if disk_percent > config.DISK_THRESHOLD:
        log_alert(
            "SYSTEM", 
            f"High disk usage detected: {disk_percent}%",
            "WARNING"
        )
    
    # Check for sudden spikes
    if len(system_metrics_history["disk"]) >= 3:
        avg_previous = sum(system_metrics_history["disk"][-3:-1]) / 2
        if disk_percent > avg_previous * 1.2 and disk_percent > 85:
            log_alert(
                "SYSTEM", 
                f"Sudden disk usage spike detected: {disk_percent}% (previous avg: {avg_previous:.1f}%)",
                "WARNING"
            )

def check_network_traffic(network_metrics):
    """
    Check network traffic for anomalies.
    
    Args:
        network_metrics (dict): Current network metrics
    """
    if len(system_metrics_history["network"]) < 2:
        return
    
    # Calculate network traffic rates
    prev_metrics = system_metrics_history["network"][-2]
    bytes_sent_rate = network_metrics["bytes_sent"] - prev_metrics["bytes_sent"]
    bytes_recv_rate = network_metrics["bytes_recv"] - prev_metrics["bytes_recv"]
    
    # Check for unusual outbound traffic (potential data exfiltration)
    if len(system_metrics_history["network"]) >= 5:
        # Calculate average outbound traffic from previous measurements
        sent_rates = []
        for i in range(1, min(5, len(system_metrics_history["network"]))):
            prev = system_metrics_history["network"][-i-1]
            curr = system_metrics_history["network"][-i]
            sent_rates.append(curr["bytes_sent"] - prev["bytes_sent"])
        
        avg_sent_rate = sum(sent_rates) / len(sent_rates) if sent_rates else 0
        
        # Alert if current rate is significantly higher than average
        if bytes_sent_rate > avg_sent_rate * 3 and bytes_sent_rate > 1000000:  # 1 MB/s
            log_alert(
                "SYSTEM", 
                f"Unusual outbound network traffic detected: {bytes_sent_rate/1000000:.2f} MB/s",
                "WARNING"
            )

def check_processes():
    """Check for suspicious processes."""
    try:
        # Get list of running processes
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            processes.append(proc.info)
        
        # Check for processes with suspicious names or command lines
        suspicious_keywords = [
            "netcat", "nc ", "ncat", "wireshark", "tcpdump", "nmap",
            "exploit", "metasploit", "backdoor", "keylogger", "rootkit"
        ]
        
        for proc in processes:
            # Check process name
            if proc['name'] and any(keyword in proc['name'].lower() for keyword in suspicious_keywords):
                log_alert(
                    "SYSTEM", 
                    f"Suspicious process detected: {proc['name']} (PID: {proc['pid']})",
                    "WARNING"
                )
            
            # Check command line
            if proc['cmdline']:
                cmdline = " ".join(proc['cmdline']).lower()
                if any(keyword in cmdline for keyword in suspicious_keywords):
                    log_alert(
                        "SYSTEM", 
                        f"Suspicious command line detected: {' '.join(proc['cmdline'])} (PID: {proc['pid']})",
                        "WARNING"
                    )
    
    except Exception as e:
        log_alert("SYSTEM", f"Error checking processes: {str(e)}", "WARNING")

def monitor_system():
    """Monitor system resources."""
    while True:
        try:
            # Get current metrics
            metrics = get_system_metrics()
            
            # Update metrics history
            update_metrics_history(metrics)
            
            # Check for anomalies
            check_cpu_usage(metrics["cpu"])
            check_memory_usage(metrics["memory"])
            check_disk_usage(metrics["disk"])
            check_network_traffic(metrics["network"])
            
            # Check for suspicious processes (less frequently)
            if int(time.time()) % 60 == 0:  # Once per minute
                check_processes()
            
            # Print debug info
            if config.DEBUG_MODE and int(time.time()) % 10 == 0:  # Every 10 seconds
                debug_print(f"System Metrics - CPU: {metrics['cpu']}%, Memory: {metrics['memory']}%, Disk: {metrics['disk']}%")
            
            # Sleep before next check
            time.sleep(5)
            
        except Exception as e:
            log_alert("SYSTEM", f"Error in system monitoring: {str(e)}", "WARNING")
            time.sleep(10)  # Sleep longer on error

def start_monitoring():
    """Start system monitoring."""
    log_alert("SYSTEM", "Starting system monitoring...", "INFO")
    
    try:
        # Start monitoring
        monitor_system()
    except Exception as e:
        log_alert("SYSTEM", f"Error in system monitoring: {str(e)}", "CRITICAL")

if __name__ == "__main__":
    start_monitoring() 