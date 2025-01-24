import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import platform
import subprocess
import time
from datetime import datetime
import socket
import sys
import json
import os
import tempfile
import atexit
import psutil

def get_application_path():
    """Get correct application path whether running as script or frozen exe"""
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

def create_lock_file():
    """Create a lock file to prevent multiple instances"""
    lock_file = os.path.join(tempfile.gettempdir(), 'network_monitor.lock')
    
    # Check if process is actually running
    if os.path.exists(lock_file):
        try:
            with open(lock_file, 'r') as f:
                pid = int(f.read().strip())
            if psutil.pid_exists(pid):
                return False  # Another instance is running
            else:
                # Stale lock file
                os.remove(lock_file)
        except (ValueError, IOError):
            # Invalid or inaccessible lock file
            try:
                os.remove(lock_file)
            except OSError:
                return False

    # Create new lock file
    try:
        with open(lock_file, 'w') as f:
            f.write(str(os.getpid()))
        atexit.register(lambda: os.remove(lock_file))
        return True
    except IOError:
        return False

def get_resource_path(relative_path):
    """Get absolute path to resource for both dev and PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def is_already_running():
    """Check if another instance is running using process name and window title"""
    current_pid = os.getpid()
    current_process = psutil.Process(current_pid)
    current_name = current_process.name()
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['pid'] != current_pid and proc.info['name'] == current_name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False

def get_app_data_path():
    """Get the appropriate application data path"""
    if platform.system() == "Windows":
        return os.path.join(os.environ['LOCALAPPDATA'], 'NetworkMonitor')
    return os.path.join(os.path.expanduser('~'), '.networkmonitor')

class PingMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Ping Monitor")
        self.root.geometry("1000x700")

        # Set up application paths
        self.app_data_path = get_app_data_path()
        os.makedirs(self.app_data_path, exist_ok=True)
        self.data_file = os.path.join(self.app_data_path, 'host_data.json')

        # Initialize application with error handling
        try:
            self.init_application()
        except Exception as e:
            messagebox.showerror("Initialization Error", str(e))
            self.root.destroy()
            sys.exit(1)

    def init_application(self):
        """Initialize the application components"""
        # Add window control
        self.root.withdraw()  # Hide initially
        self.running = True
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Store hosts and their monitoring threads
        self.hosts = {}
        self.monitoring_threads = {}
        self.queue = queue.Queue()

        # Create frames
        self.create_main_frame()
        self.create_input_frame()
        self.create_monitor_frame()
        self.create_stats_frame()

        # Load saved hosts
        self.load_hosts()

        # Start update thread
        self.update_thread = threading.Thread(target=self.update_display, daemon=True)
        self.update_thread.start()

        # Show window after initialization
        self.root.after(100, self.root.deiconify)

    def create_main_frame(self):
        """Create and configure main frame"""
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky='nsew')
        
        # Configure weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

    def load_hosts(self):
        """Load saved hosts from JSON file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    saved_hosts = json.load(f)
                    for host_data in saved_hosts:
                        self.add_host_from_data(
                            host_data['hostname'],
                            host_data['ip'],
                            float(host_data['threshold'])
                        )
        except Exception as e:
            messagebox.showwarning("Warning", f"Error loading saved hosts: {str(e)}")

    def save_hosts(self):
        """Save hosts to JSON file with error handling"""
        try:
            os.makedirs(self.app_data_path, exist_ok=True)
            with open(self.data_file, 'w') as f:
                hosts_data = []
                for (hostname, ip) in self.hosts.keys():
                    item = self.hosts[(hostname, ip)]
                    values = self.tree.item(item)['values']
                    hosts_data.append({
                        'hostname': hostname,
                        'ip': ip,
                        'threshold': values[8]
                    })
                json.dump(hosts_data, f, indent=4)
        except Exception as e:
            messagebox.showwarning("Warning", f"Error saving hosts: {str(e)}")

    def add_host_from_data(self, hostname, ip, threshold):
        """Add a host from saved data"""
        host_key = (hostname, ip)
        if host_key not in self.hosts:
            item = self.tree.insert("", tk.END, values=(
                hostname, ip, "Unknown", "N/A", "N/A", "N/A", "N/A", "N/A", threshold, "N/A"
            ))
            self.hosts[host_key] = item

            thread = threading.Thread(
                target=self.monitor_host,
                args=(hostname, ip, threshold),
                daemon=True
            )
            self.monitoring_threads[host_key] = thread
            thread.start()

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

        # Add and Remove buttons
        ttk.Button(self.input_frame, text="Add Host", command=self.add_host).grid(row=0, column=6, padx=5)
        ttk.Button(self.input_frame, text="Remove Selected", command=self.remove_selected_host).grid(row=0, column=7, padx=5)
        ttk.Button(self.input_frame, text="Clear All", command=self.clear_all_hosts).grid(row=0, column=8, padx=5)
    

    def remove_selected_host(self):
        """Remove selected host from monitoring"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select a host to remove")
            return

        for item in selected_items:
            values = self.tree.item(item)['values']
            host_key = (values[0], values[1])  # hostname, ip

            # Remove from monitoring
            if host_key in self.monitoring_threads:
                self.monitoring_threads.pop(host_key)

            # Remove from hosts dictionary
            if host_key in self.hosts:
                self.hosts.pop(host_key)

            # Remove from tree
            self.tree.delete(item)

        # Save updated hosts
        self.save_hosts()
        self.update_stats()
    def clear_all_hosts(self):
        """Remove all hosts from monitoring"""
        for host_key in list(self.hosts.keys()):
            item = self.hosts[host_key]

            # Remove from monitoring
            if host_key in self.monitoring_threads:
                self.monitoring_threads.pop(host_key)

            # Remove from hosts dictionary
            if host_key in self.hosts:
                self.hosts.pop(host_key)

            # Remove from tree
            self.tree.delete(item)

        # Save updated hosts
        self.save_hosts()
        self.update_stats()

    def create_monitor_frame(self):
        self.monitor_frame = ttk.LabelFrame(self.main_frame, text="Monitoring", padding="5")
        self.monitor_frame.grid(row=1, column=0, columnspan=2, sticky='nsew', pady=5)
    
    # Make monitor frame responsive
        self.monitor_frame.grid_rowconfigure(0, weight=1)
        self.monitor_frame.grid_columnconfigure(0, weight=1)

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
        self.tree.grid(row=0, column=0, sticky='nsew')

        for header, width in headers.items():
            self.tree.heading(header, text=header)
            self.tree.column(header, width=width)

        self.tree.tag_configure("good", background="#90EE90")
        self.tree.tag_configure("high", background="#FFD700")
        self.tree.tag_configure("critical", background="#FF6B6B")

        # Add scrollbars
        vsb = ttk.Scrollbar(self.monitor_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        hsb = ttk.Scrollbar(self.monitor_frame, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky='ew')
    
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

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
        """Resolve hostname to IP or vice versa"""
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
                hostname = ip

        # Check if host already exists
        host_key = (hostname, ip)
        if host_key in self.hosts:
            messagebox.showerror("Error", "Host already exists")
            return

        self.add_host_from_data(hostname, ip, threshold)
        self.save_hosts()

        # Clear entries
        self.hostname_entry.delete(0, tk.END)
        self.ip_entry.delete(0, tk.END)
        self.threshold_entry.delete(0, tk.END)
        self.threshold_entry.insert(0, "100")

        self.update_stats()

    def ping(self, ip):
        """Perform a single ping and return (ping_time, success)"""
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

            return ping_time, success
        except Exception:
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

    def update_stats(self):
        """Update statistics display"""
        total = len(self.hosts)
        active = sum(1 for item in self.tree.get_children() if self.tree.item(item)['values'][2] != "Critical")
        inactive = total - active

        self.stats_labels['total'].configure(text=f"Total: {total}")
        self.stats_labels['active'].configure(text=f"Active: {active}")
        self.stats_labels['inactive'].configure(text=f"Inactive: {inactive}")

    def update_display(self):
        """Update the display with ping results"""
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
        """Handle application closing"""
        try:
            self.save_hosts()
            self.running = False
            
            # Stop all monitoring threads
            for thread in self.monitoring_threads.values():
                thread.join(timeout=1)
            
            # Clean up temp files
            lock_file = os.path.join(tempfile.gettempdir(), 'network_monitor.lock')
            if os.path.exists(lock_file):
                try:
                    os.remove(lock_file)
                except OSError:
                    pass
                    
        finally:
            self.root.quit()
            self.root.destroy()

if __name__ == "__main__":
    try:
        # Ensure single instance using a more reliable method
        mutex_name = "Global\\NetworkMonitorMutex"
        if platform.system() == "Windows":
            try:
                import win32event
                import win32api
                import winerror
                mutex = win32event.CreateMutex(None, 1, mutex_name)
                if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
                    messagebox.showerror("Error", "Application is already running!")
                    sys.exit(1)
            except ImportError:
                # Fallback to basic process check if win32 is not available
                if is_already_running():
                    messagebox.showerror("Error", "Application is already running!")
                    sys.exit(1)
        else:
            # Use file-based lock for non-Windows systems
            lock_file = os.path.join(tempfile.gettempdir(), 'network_monitor.lock')
            if os.path.exists(lock_file):
                try:
                    with open(lock_file, 'r') as f:
                        pid = int(f.read().strip())
                    if psutil.pid_exists(pid):
                        messagebox.showerror("Error", "Application is already running!")
                        sys.exit(1)
                except:
                    pass
            with open(lock_file, 'w') as f:
                f.write(str(os.getpid()))

        # Hide console in frozen mode
        if getattr(sys, 'frozen', False) and platform.system() == "Windows":
            import ctypes
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0)

        root = tk.Tk()
        app = PingMonitor(root)
        root.mainloop()

    except Exception as e:
        messagebox.showerror("Error", f"Application error: {str(e)}")
        sys.exit(1)