import tkinter as tk
from tkinter import ttk, messagebox
import config

class IDSConfigGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System Configuration")
        self.root.geometry("400x400")

        # Create tabs
        self.tab_control = ttk.Notebook(root)
        self.network_tab = ttk.Frame(self.tab_control)
        self.system_tab = ttk.Frame(self.tab_control)
        self.log_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.network_tab, text='Network Settings')
        self.tab_control.add(self.system_tab, text='System Settings')
        self.tab_control.add(self.log_tab, text='Log Settings')
        self.tab_control.pack(expand=1, fill='both')

        self.create_network_tab()
        self.create_system_tab()
        self.create_log_tab()

    def create_network_tab(self):
        # Network Settings
        ttk.Label(self.network_tab, text="Network Interface:").grid(column=0, row=0, padx=10, pady=10)
        self.interface_entry = ttk.Entry(self.network_tab)
        self.interface_entry.grid(column=1, row=0, padx=10, pady=10)
        self.interface_entry.insert(0, config.INTERFACE)

        ttk.Label(self.network_tab, text="Packet Count:").grid(column=0, row=1, padx=10, pady=10)
        self.packet_count_entry = ttk.Entry(self.network_tab)
        self.packet_count_entry.grid(column=1, row=1, padx=10, pady=10)
        self.packet_count_entry.insert(0, config.PACKET_COUNT)

        ttk.Label(self.network_tab, text="Suspicious Ports (comma-separated):").grid(column=0, row=2, padx=10, pady=10)
        self.suspicious_ports_entry = ttk.Entry(self.network_tab)
        self.suspicious_ports_entry.grid(column=1, row=2, padx=10, pady=10)
        self.suspicious_ports_entry.insert(0, ', '.join(map(str, config.SUSPICIOUS_PORTS)))

        ttk.Button(self.network_tab, text="Save", command=self.save_network_settings).grid(column=0, row=3, columnspan=2, pady=20)

    def create_system_tab(self):
        # System Settings
        ttk.Label(self.system_tab, text="CPU Threshold (%):").grid(column=0, row=0, padx=10, pady=10)
        self.cpu_threshold_entry = ttk.Entry(self.system_tab)
        self.cpu_threshold_entry.grid(column=1, row=0, padx=10, pady=10)
        self.cpu_threshold_entry.insert(0, config.CPU_THRESHOLD)

        ttk.Label(self.system_tab, text="Memory Threshold (%):").grid(column=0, row=1, padx=10, pady=10)
        self.memory_threshold_entry = ttk.Entry(self.system_tab)
        self.memory_threshold_entry.grid(column=1, row=1, padx=10, pady=10)
        self.memory_threshold_entry.insert(0, config.MEMORY_THRESHOLD)

        ttk.Label(self.system_tab, text="Disk Threshold (%):").grid(column=0, row=2, padx=10, pady=10)
        self.disk_threshold_entry = ttk.Entry(self.system_tab)
        self.disk_threshold_entry.grid(column=1, row=2, padx=10, pady=10)
        self.disk_threshold_entry.insert(0, config.DISK_THRESHOLD)

        ttk.Button(self.system_tab, text="Save", command=self.save_system_settings).grid(column=0, row=3, columnspan=2, pady=20)

    def create_log_tab(self):
        # Log Settings
        ttk.Label(self.log_tab, text="Log Files (comma-separated):").grid(column=0, row=0, padx=10, pady=10)
        self.log_files_entry = ttk.Entry(self.log_tab)
        self.log_files_entry.grid(column=1, row=0, padx=10, pady=10)
        self.log_files_entry.insert(0, ', '.join(config.LOG_FILES))

        ttk.Label(self.log_tab, text="Log Patterns (comma-separated):").grid(column=0, row=1, padx=10, pady=10)
        self.log_patterns_entry = ttk.Entry(self.log_tab)
        self.log_patterns_entry.grid(column=1, row=1, padx=10, pady=10)
        self.log_patterns_entry.insert(0, ', '.join(config.LOG_PATTERNS))

        ttk.Button(self.log_tab, text="Save", command=self.save_log_settings).grid(column=0, row=2, columnspan=2, pady=20)

    def save_network_settings(self):
        try:
            config.INTERFACE = self.interface_entry.get()
            config.PACKET_COUNT = int(self.packet_count_entry.get())
            config.SUSPICIOUS_PORTS = list(map(int, self.suspicious_ports_entry.get().split(',')))
            messagebox.showinfo("Success", "Network settings saved successfully!")
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Please check your entries.")

    def save_system_settings(self):
        try:
            config.CPU_THRESHOLD = int(self.cpu_threshold_entry.get())
            config.MEMORY_THRESHOLD = int(self.memory_threshold_entry.get())
            config.DISK_THRESHOLD = int(self.disk_threshold_entry.get())
            messagebox.showinfo("Success", "System settings saved successfully!")
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Please check your entries.")

    def save_log_settings(self):
        config.LOG_FILES = self.log_files_entry.get().split(',')
        config.LOG_PATTERNS = self.log_patterns_entry.get().split(',')
        messagebox.showinfo("Success", "Log settings saved successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSConfigGUI(root)
    root.mainloop()
