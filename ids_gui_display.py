import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import threading
import time
import config

class IDSDisplayGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System Display")
        self.root.geometry("600x400")

        # Create a scrolled text area for displaying logs
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        self.log_area.pack(expand=True, fill='both')

        # Create a frame for settings
        self.settings_frame = ttk.LabelFrame(root, text="Settings")
        self.settings_frame.pack(pady=10, padx=10, fill='x')

        # Network Interface
        ttk.Label(self.settings_frame, text="Network Interface:").grid(column=0, row=0, padx=10, pady=5)
        self.interface_entry = ttk.Entry(self.settings_frame)
        self.interface_entry.grid(column=1, row=0, padx=10, pady=5)
        self.interface_entry.insert(0, config.INTERFACE)

        # Packet Count
        ttk.Label(self.settings_frame, text="Packet Count:").grid(column=0, row=1, padx=10, pady=5)
        self.packet_count_entry = ttk.Entry(self.settings_frame)
        self.packet_count_entry.grid(column=1, row=1, padx=10, pady=5)
        self.packet_count_entry.insert(0, config.PACKET_COUNT)

        # Suspicious Ports
        ttk.Label(self.settings_frame, text="Suspicious Ports:").grid(column=0, row=2, padx=10, pady=5)
        self.suspicious_ports_entry = ttk.Entry(self.settings_frame)
        self.suspicious_ports_entry.grid(column=1, row=2, padx=10, pady=5)
        self.suspicious_ports_entry.insert(0, ', '.join(map(str, config.SUSPICIOUS_PORTS)))

        # Save Settings Button
        ttk.Button(self.settings_frame, text="Save Settings", command=self.save_settings).grid(column=0, row=3, columnspan=2, pady=10)

        # Start a thread to simulate IDS monitoring
        self.monitor_thread = threading.Thread(target=self.simulate_ids_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def simulate_ids_monitoring(self):
        """Simulate IDS monitoring and log output."""
        while True:
            # Simulate generating an alert
            self.log_alert("INFO", "Monitoring network traffic...")
            time.sleep(5)  # Simulate time delay between updates

    def log_alert(self, severity, message):
        """Log an alert to the GUI."""
        log_message = f"[{severity}] {message}\n"
        self.log_area.insert(tk.END, log_message)
        self.log_area.see(tk.END)  # Scroll to the end

    def save_settings(self):
        """Save the settings from the GUI to the config."""
        try:
            config.INTERFACE = self.interface_entry.get()
            config.PACKET_COUNT = int(self.packet_count_entry.get())
            config.SUSPICIOUS_PORTS = list(map(int, self.suspicious_ports_entry.get().split(',')))
            messagebox.showinfo("Success", "Settings saved successfully!")
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Please check your entries.")

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSDisplayGUI(root)
    root.mainloop() 