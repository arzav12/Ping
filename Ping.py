import tkinter as tk
from tkinter import ttk, messagebox
import socket
import sys
import threading
import queue
import platform
import subprocess
import time
from datetime import datetime
import re

class SingleInstanceChecker:
    def __init__(self, port=12345):
        self.port = port
        
    def check(self):
        try:
            # Try to create a socket server
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(('localhost', self.port))
            self.sock.listen(1)
            return True
        except socket.error:
            return False

class PingMonitor:
    def __init__(self, root):
        # Check if another instance is running
        self.instance_checker = SingleInstanceChecker()
        if not self.instance_checker.check():
            messagebox.showwarning("Warning", "Application is already running!")
            root.destroy()
            sys.exit(0)
            
        self.root = root
        self.root.title("Advanced Network Ping Monitor")
        self.root.geometry("1000x700")
        
        # Store hosts and their monitoring threads
        self.hosts = {}
        self.monitoring_threads = {}
        self.queue = queue.Queue()
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create UI components (your existing code)
        self.create_input_frame()
        self.create_monitor_frame()
        self.create_stats_frame()
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Start update thread
        self.update_thread = threading.Thread(target=self.update_display, daemon=True)
        self.update_thread.start()

    def on_closing(self):
        """Handle application shutdown"""
        try:
            # Clean up socket
            if hasattr(self, 'instance_checker'):
                self.instance_checker.sock.close()
        except:
            pass
        self.root.destroy()
        sys.exit(0)

    def create_input_frame(self):
        """Create the input frame with host and IP address fields"""
        self.input_frame = ttk.LabelFrame(self.main_frame, text="Add New Host", padding="10")
        self.input_frame.grid(row=0, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))

        # Hostname input
        ttk.Label(self.input_frame, text="Hostname:").grid(row=0, column=0, padx=5)
        self.hostname_entry = ttk.Entry(self.input_frame, width=30)
        self.hostname_entry.grid(row=0, column=1, padx=5)

        # IP address input
        ttk.Label(self.input_frame, text="IP Address:").grid(row=0, column=2, padx=5)
        self.ip_entry = ttk.Entry(self.input_frame, width=20)
        self.ip_entry.grid(row=0, column=3, padx=5)

        # Threshold input
        ttk.Label(self.input_frame, text="Threshold (ms):").grid(row=0, column=4, padx=5)
        self.threshold_entry = ttk.Entry(self.input_frame, width=10)
        self.threshold_entry.insert(0, "100")
        self.threshold_entry.grid(row=0, column=5, padx=5)

        # Add and Remove buttons
        ttk.Button(self.input_frame, text="Add Host", command=self.add_host).grid(row=0, column=6, padx=5)
        ttk.Button(self.input_frame, text="Remove Selected", command=self.remove_host).grid(row=0, column=7, padx=5)
        ttk.Button(self.input_frame, text="Clear All", command=self.clear_all_hosts).grid(row=0, column=8, padx=5)

    def create_monitor_frame(self):
        """Create the monitor frame with the treeview"""
        self.monitor_frame = ttk.LabelFrame(self.main_frame, text="Monitor Status", padding="10")
        self.monitor_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure column headers
        self.tree = ttk.Treeview(self.monitor_frame,
                                 columns=("Hostname", "IP", "Status", "Ping", "Min", "Max", "Avg", "Loss%", "Threshold",
                                          "Last Update"),
                                 show="headings")

        headers = {
            "Hostname": 150,
            "IP": 120,
            "Status": 80,
            "Ping": 80,
            "Min": 80,
            "Max": 80,
            "Avg": 80,
            "Loss%": 80,
            "Threshold": 80,
            "Last Update": 150
        }

        for header, width in headers.items():
            self.tree.heading(header, text=header)
            self.tree.column(header, width=width)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.monitor_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Configure monitor frame grid weights
        self.monitor_frame.grid_rowconfigure(0, weight=1)
        self.monitor_frame.grid_columnconfigure(0, weight=1)

    def create_stats_frame(self):
        """Create the statistics frame"""
        self.stats_frame = ttk.LabelFrame(self.main_frame, text="Statistics", padding="10")
        self.stats_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))

        self.stats_labels = {
            'total': ttk.Label(self.stats_frame, text="Total Hosts: 0"),
            'active': ttk.Label(self.stats_frame, text="Active: 0"),
            'inactive': ttk.Label(self.stats_frame, text="Inactive: 0")
        }

        for i, label in enumerate(self.stats_labels.values()):
            label.grid(row=0, column=i, padx=20)

    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False

    def validate_hostname(self, hostname):
        """Validate hostname format"""
        if not hostname:
            return False
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def resolve_host(self, hostname_or_ip):
        """Resolve hostname to IP or vice versa"""
        try:
            if self.validate_ip(hostname_or_ip):
                return socket.gethostbyaddr(hostname_or_ip)[0], hostname_or_ip
            else:
                return hostname_or_ip, socket.gethostbyname(hostname_or_ip)
        except:
            return None, None

    def ping(self, host):
        """Ping the specified host and return the response time"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        count_param = '1'
        command = ['ping', param, count_param, host]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode().strip()
            if platform.system().lower() == 'windows':
                if 'TTL=' in output:
                    ms = output.split('Average = ')[-1].split('ms')[0]
                    return float(ms), True
            else:
                if 'time=' in output:
                    ms = output.split('time=')[-1].split(' ')[0]
                    return float(ms), True
            return None, False
        except:
            return None, False

    def monitor_host(self, hostname, ip, threshold):
        """Continuously monitor a host and update its status"""
        ping_history = []
        packet_loss = 0
        total_pings = 0

        while (hostname, ip) in self.hosts:
            total_pings += 1
            ping_time, success = self.ping(ip)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if success and ping_time is not None:
                ping_history.append(ping_time)
                if len(ping_history) > 100:  # Keep last 100 pings
                    ping_history.pop(0)

                min_ping = min(ping_history)
                max_ping = max(ping_history)
                avg_ping = sum(ping_history) / len(ping_history)
                loss_percentage = (packet_loss / total_pings) * 100

                status = "Good" if ping_time < threshold else "High"
                self.queue.put((hostname, ip, status, ping_time, min_ping, max_ping, avg_ping,
                                loss_percentage, threshold, timestamp))
            else:
                packet_loss += 1
                loss_percentage = (packet_loss / total_pings) * 100
                self.queue.put((hostname, ip, "Down", None, None, None, None,
                                loss_percentage, threshold, timestamp))

            time.sleep(2)  # Wait 2 seconds between pings

    def add_host(self):
        """Add a new host to monitor"""
        hostname = self.hostname_entry.get().strip()
        ip = self.ip_entry.get().strip()

        try:
            threshold = float(self.threshold_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid threshold value")
            return

        if not hostname and not ip:
            messagebox.showerror("Error", "Please enter either hostname or IP address")
            return

        # If only one field is filled, try to resolve the other
        if not ip and hostname:
            resolved_hostname, resolved_ip = self.resolve_host(hostname)
            if resolved_ip:
                ip = resolved_ip
                hostname = resolved_hostname
        elif not hostname and ip:
            resolved_hostname, resolved_ip = self.resolve_host(ip)
            if resolved_hostname:
                hostname = resolved_hostname
                ip = resolved_ip

        if not ip or not hostname:
            messagebox.showerror("Error", "Could not resolve host")
            return

        if (hostname, ip) in self.hosts:
            messagebox.showerror("Error", "Host already being monitored")
            return

        # Test if host is reachable
        ping_time, success = self.ping(ip)
        if not success:
            if not messagebox.askyesno("Warning",
                                       "Host appears to be unreachable. Add it anyway?"):
                return

        # Add host to monitoring
        self.hosts[(hostname, ip)] = self.tree.insert("", tk.END,
                                                      values=(hostname, ip, "Initializing...", "", "", "", "", "", threshold,
                                                              ""))

        # Start monitoring thread
        thread = threading.Thread(target=self.monitor_host,
                                  args=(hostname, ip, threshold),
                                  daemon=True)
        self.monitoring_threads[(hostname, ip)] = thread
        thread.start()

        # Clear input fields
        self.hostname_entry.delete(0, tk.END)
        self.ip_entry.delete(0, tk.END)

        self.update_stats()

    def remove_host(self):
        """Remove selected host from monitoring"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a host to remove")
            return

        for item in selected:
            values = self.tree.item(item)['values']
            host_key = (values[0], values[1])  # (hostname, ip)
            if host_key in self.hosts:
                del self.hosts[host_key]
                self.tree.delete(item)

        self.update_stats()

    def clear_all_hosts(self):
        """Remove all hosts from monitoring"""
        if messagebox.askyesno("Confirm", "Are you sure you want to remove all hosts?"):
            self.hosts.clear()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.update_stats()

    def update_stats(self):
        """Update statistics display"""
        total = len(self.hosts)
        active = sum(1 for item in self.tree.get_children()
                     if self.tree.item(item)['values'][2] != "Down")
        inactive = total - active

        self.stats_labels['total'].configure(text=f"Total Hosts: {total}")
        self.stats_labels['active'].configure(text=f"Active: {active}")
        self.stats_labels['inactive'].configure(text=f"Inactive: {inactive}")

    def update_display(self):
        """Update the display with ping results"""
        while True:
            try:
                (hostname, ip, status, ping_time, min_ping, max_ping, avg_ping,
                 loss_percentage, threshold, timestamp) = self.queue.get(timeout=1)

                host_key = (hostname, ip)
                if host_key in self.hosts:
                    item = self.hosts[host_key]
                    ping_str = f"{ping_time:.1f}" if ping_time is not None else "N/A"
                    min_str = f"{min_ping:.1f}" if min_ping is not None else "N/A"
                    max_str = f"{max_ping:.1f}" if max_ping is not None else "N/A"
                    avg_str = f"{avg_ping:.1f}" if avg_ping is not None else "N/A"
                    loss_str = f"{loss_percentage:.1f}%" if loss_percentage is not None else "N/A"

                    # Set tag for row color
                    if status == "Good":
                        tag = "good"
                        self.tree.tag_configure(tag, background="#90EE90")  # Light green
                    elif status == "High":
                        tag = "high"
                        self.tree.tag_configure(tag, background="#FFB6C1")  # Light red
                    else:
                        tag = "down"
                        self.tree.tag_configure(tag, background="#D3D3D3")  # Light gray

                    self.tree.item(item, values=(
                        hostname, ip, status, ping_str, min_str, max_str,
                        avg_str, loss_str, threshold, timestamp
                    ), tags=(tag,))

                    self.update_stats()

            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error updating display: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PingMonitor(root)
    root.mainloop()
