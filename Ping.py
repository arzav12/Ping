import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import platform
import subprocess
import time
from datetime import datetime
import socket
import re
from tendo import singleton
import sys

class PingMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Ping Monitor")
        self.root.geometry("1000x700")
        
        # Add window control
        self.root.withdraw()  # Hide initially
        self.running = True
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Store hosts and their monitoring threads
        self.hosts = {}
        self.monitoring_threads = {}
        self.queue = queue.Queue()

        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Create frames
        self.create_input_frame()
        self.create_monitor_frame()
        self.create_stats_frame()

        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        # Start update thread
        self.update_thread = threading.Thread(target=self.update_display, daemon=True)
        self.update_thread.start()

        # Show window after initialization
        self.root.after(100, self.root.deiconify)

    def create_input_frame(self):
        self.input_frame = ttk.LabelFrame(self.main_frame, text="Add Host", padding="5")
        self.input_frame.grid(row=0, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))

        # Host entry
        ttk.Label(self.input_frame, text="Hostname:").grid(row=0, column=0, padx=5)
        self.hostname_entry = ttk.Entry(self.input_frame)
        self.hostname_entry.grid(row=0, column=1, padx=5)

        # IP entry
        ttk.Label(self.input_frame, text="IP Address:").grid(row=0, column=2, padx=5)
        self.ip_entry = ttk.Entry(self.input_frame)
        self.ip_entry.grid(row=0, column=3, padx=5)

        # Threshold entry
        ttk.Label(self.input_frame, text="Threshold (ms):").grid(row=0, column=4, padx=5)
        self.threshold_entry = ttk.Entry(self.input_frame)
        self.threshold_entry.insert(0, "100")
        self.threshold_entry.grid(row=0, column=5, padx=5)

        # Add button
        self.add_button = ttk.Button(self.input_frame, text="Add Host", command=self.add_host)
        self.add_button.grid(row=0, column=6, padx=5)

    def create_monitor_frame(self):
        self.monitor_frame = ttk.LabelFrame(self.main_frame, text="Monitoring", padding="5")
        self.monitor_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

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

        self.tree = ttk.Treeview(self.monitor_frame, columns=list(headers.keys()), show="headings")
        
        for header, width in headers.items():
            self.tree.heading(header, text=header)
            self.tree.column(header, width=width)

        self.tree.tag_configure("good", background="#90EE90")  # Light green
        self.tree.tag_configure("high", background="#FFD700")  # Gold
        self.tree.tag_configure("critical", background="#FF6B6B")  # Light red

        scrollbar = ttk.Scrollbar(self.monitor_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

    def create_stats_frame(self):
        self.stats_frame = ttk.LabelFrame(self.main_frame, text="Statistics", padding="5")
        self.stats_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.stats_labels = {}
        self.stats_labels['total'] = ttk.Label(self.stats_frame, text="Total: 0")
        self.stats_labels['active'] = ttk.Label(self.stats_frame, text="Active: 0")
        self.stats_labels['inactive'] = ttk.Label(self.stats_frame, text="Inactive: 0")

        for i, label in enumerate(self.stats_labels.values()):
            label.grid(row=0, column=i, padx=10)

    def resolve_host(self, host):
        try:
            ip = socket.gethostbyname(host)
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname, ip
        except socket.error:
            return None, None

    def add_host(self):
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
            else:
                messagebox.showerror("Error", "Could not resolve hostname")
                return
        elif not hostname and ip:
            resolved_hostname, resolved_ip = self.resolve_host(ip)
            if resolved_hostname:
                hostname = resolved_hostname
            else:
                hostname = ip  # Use IP as hostname if resolution fails

        # Check if host already exists
        host_key = (hostname, ip)
        if host_key in self.hosts:
            messagebox.showerror("Error", "Host already exists")
            return

        # Add to treeview and start monitoring
        item = self.tree.insert("", tk.END, values=(hostname, ip, "Unknown", "N/A", "N/A", "N/A", "N/A", "N/A", threshold, "N/A"))
        self.hosts[host_key] = item

        thread = threading.Thread(target=self.monitor_host, args=(hostname, ip, threshold), daemon=True)
        self.monitoring_threads[host_key] = thread
        thread.start()

        # Clear entries
        self.hostname_entry.delete(0, tk.END)
        self.ip_entry.delete(0, tk.END)
        self.threshold_entry.delete(0, tk.END)
        self.threshold_entry.insert(0, "100")

        self.update_stats()

    def monitor_host(self, hostname, ip, threshold):
        while self.running:
            try:
                ping_result = self.ping_host(ip)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if ping_result[0]:  # Successful ping
                    ping_time = ping_result[1]
                    status = "Good" if ping_time < threshold else ("High" if ping_time < threshold * 2 else "Critical")
                    self.queue.put((hostname, ip, status, ping_time, ping_time, ping_time, ping_time, 0, threshold, timestamp))
                else:
                    self.queue.put((hostname, ip, "Critical", None, None, None, None, 100, threshold, timestamp))
                
                time.sleep(1)
            except Exception as e:
                print(f"Error monitoring {hostname}: {e}")
                time.sleep(1)

    def ping_host(self, ip):
        try:
            if platform.system().lower() == "windows":
                cmd = f"ping -n 1 {ip}"
            else:
                cmd = f"ping -c 1 {ip}"
            
            start_time = time.time()
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            end_time = time.time()
            
            success = result.returncode == 0
            ping_time = (end_time - start_time) * 1000 if success else None
            
            return success, ping_time
        except Exception:
            return False, None

    def update_stats(self):
        total = len(self.hosts)
        active = sum(1 for item in self.tree.get_children() if self.tree.item(item)['values'][2] != "Critical")
        inactive = total - active

        self.stats_labels['total'].configure(text=f"Total: {total}")
        self.stats_labels['active'].configure(text=f"Active: {active}")
        self.stats_labels['inactive'].configure(text=f"Inactive: {inactive}")

    def update_display(self):
        while self.running:
            try:
                update = self.queue.get(timeout=0.1)
                hostname, ip, status, ping_time, min_ping, max_ping, avg_ping, loss_percentage, threshold, timestamp = update
                
                host_key = (hostname, ip)
                if host_key in self.hosts:
                    ping_str = f"{ping_time:.1f}" if ping_time is not None else "N/A"
                    min_str = f"{min_ping:.1f}" if min_ping is not None else "N/A"
                    max_str = f"{max_ping:.1f}" if max_ping is not None else "N/A"
                    avg_str = f"{avg_ping:.1f}" if avg_ping is not None else "N/A"
                    loss_str = f"{loss_percentage:.1f}%" if loss_percentage is not None else "N/A"

                    tag = "good" if status == "Good" else ("high" if status == "High" else "critical")
                    
                    self.tree.item(
                        self.hosts[host_key],
                        values=(
                            hostname, ip, status, ping_str, min_str, max_str,
                            avg_str, loss_str, threshold, timestamp
                        ),
                        tags=(tag,)
                    )
                    self.update_stats()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error updating display: {e}")
            finally:
                time.sleep(0.1)

    def on_closing(self):
        self.running = False
        for thread in self.monitoring_threads.values():
            thread.join(timeout=1)
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    try:
        # Hide console window
        if platform.system() == "Windows":
            import ctypes
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0)
        
        me = singleton.SingleInstance()
        root = tk.Tk()
        app = PingMonitor(root)
        root.mainloop()
        
    except singleton.SingleInstanceException:
        messagebox.showerror("Error", "Application is already running!")
        sys.exit(1)