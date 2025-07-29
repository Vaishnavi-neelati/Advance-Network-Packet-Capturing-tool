import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import csv
from datetime import datetime
import re
import socket
from collections import defaultdict
import sys

# Try to import matplotlib with fallback
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available - visualization features disabled")

# Protocol filters using lambda functions
protocol_filters = {
    "TCP": lambda pkt: TCP in pkt,
    "UDP": lambda pkt: UDP in pkt,
    "ICMP": lambda pkt: ICMP in pkt,
    "FTP": lambda pkt: TCP in pkt and (pkt[TCP].sport == 21 or pkt[TCP].dport == 21),
    "HTTP": lambda pkt: TCP in pkt and (pkt[TCP].sport == 80 or pkt[TCP].dport == 80),
    "HTTPS": lambda pkt: TCP in pkt and (pkt[TCP].sport == 443 or pkt[TCP].dport == 443),
    "DNS": lambda pkt: UDP in pkt and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53),
    "SSH": lambda pkt: TCP in pkt and (pkt[TCP].sport == 22 or pkt[TCP].dport == 22),
    "SMTP": lambda pkt: TCP in pkt and (pkt[TCP].sport == 25 or pkt[TCP].dport == 25),
}

# Protocol color mapping for visualization
protocol_colors = {
    "TCP": "#1f77b4",
    "UDP": "#ff7f0e",
    "ICMP": "#2ca02c",
    "HTTP": "#d62728",
    "HTTPS": "#9467bd",
    "DNS": "#8c564b",
    "FTP": "#e377c2",
    "SSH": "#7f7f7f",
    "SMTP": "#bcbd22",
    "Other": "#17becf"
}

def is_valid_ip(ip):
    """Check if the IP address is valid"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(0 <= int(num) <= 255 for num in ip.split('.'))
    return False

def get_hostname(ip):
    """Try to resolve IP to hostname"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Packet Sniffer")
        self.root.geometry("1300x850")
        self.root.minsize(1100, 750)

        # Capture data
        self.captured_packets = []
        self.packet_counter = 1
        self.ip_filter = None
        self.protocol_filter = None
        self.protocol_stats = defaultdict(int)
        self.traffic_stats = {"incoming": 0, "outgoing": 0}
        self.hostname_resolution = True
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Treeview', font=('Consolas', 9), rowheight=25)
        self.style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))

        # Main container
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top control panel frame
        self.top_control_frame = ttk.Frame(self.main_frame)
        self.top_control_frame.pack(fill=tk.X, pady=(0, 10))

        # IP Filter frame
        self.ip_filter_frame = ttk.LabelFrame(self.top_control_frame, text="IP Filter", padding=(10, 5))
        self.ip_filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        ttk.Label(self.ip_filter_frame, text="Filter by IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(self.ip_filter_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        self.set_ip_btn = ttk.Button(self.ip_filter_frame, text="Set Filter", command=self.set_ip_filter)
        self.set_ip_btn.pack(side=tk.LEFT, padx=2)

        self.clear_ip_btn = ttk.Button(self.ip_filter_frame, text="Clear Filter", command=self.clear_ip_filter)
        self.clear_ip_btn.pack(side=tk.LEFT)

        # Protocol Filter frame
        self.proto_filter_frame = ttk.LabelFrame(self.top_control_frame, text="Protocol Filter", padding=(10, 5))
        self.proto_filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.protocol_var = tk.StringVar()
        self.protocol_var.set("All")  # Default to show all protocols

        protocols = ["All", "TCP", "UDP", "ICMP"]
        for proto in protocols:
            rb = ttk.Radiobutton(
                self.proto_filter_frame,
                text=proto,
                variable=self.protocol_var,
                value=proto,
                command=self.set_protocol_filter
            )
            rb.pack(side=tk.LEFT, padx=5)

        # Status label
        self.filter_status = ttk.Label(self.ip_filter_frame, text="No IP filter set")
        self.filter_status.pack(side=tk.RIGHT, padx=10)

        # Control panel frame
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding=(10, 5))
        self.control_frame.pack(fill=tk.X, pady=(0, 10))

        # Protocol filter checkboxes (for detailed protocol filtering)
        self.filter_frame = ttk.LabelFrame(self.control_frame, text="Protocol Checkboxes", padding=(10, 5))
        self.filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.protocol_vars = {}
        for i, proto in enumerate(protocol_filters):
            self.protocol_vars[proto] = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(self.filter_frame, text=proto, variable=self.protocol_vars[proto])
            chk.grid(row=i // 4, column=i % 4, sticky="w", padx=5, pady=2)

        # Button frame
        self.button_frame = ttk.Frame(self.control_frame)
        self.button_frame.pack(side=tk.RIGHT, fill=tk.Y)

        # Control buttons
        self.start_btn = ttk.Button(self.button_frame, text="Start Capture", command=self.start_sniffing)
        self.start_btn.pack(fill=tk.X, pady=2)

        self.stop_btn = ttk.Button(self.button_frame, text="Stop Capture", command=self.stop_sniffing, state="disabled")
        self.stop_btn.pack(fill=tk.X, pady=2)

        self.export_btn = ttk.Button(self.button_frame, text="Export to CSV", command=self.export_to_csv)
        self.export_btn.pack(fill=tk.X, pady=2)

        self.clear_btn = ttk.Button(self.button_frame, text="Clear Data", command=self.clear_data)
        self.clear_btn.pack(fill=tk.X, pady=2)

        self.analyze_btn = ttk.Button(self.button_frame, text="Show Stats", command=self.show_statistics)
        self.analyze_btn.pack(fill=tk.X, pady=2)

        # Additional options frame
        self.options_frame = ttk.Frame(self.control_frame)
        self.options_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        self.hostname_var = tk.BooleanVar(value=True)
        self.hostname_chk = ttk.Checkbutton(
            self.options_frame, 
            text="Resolve Hostnames", 
            variable=self.hostname_var,
            command=self.toggle_hostname_resolution
        )
        self.hostname_chk.pack(pady=2)

        self.alert_var = tk.BooleanVar(value=True)
        self.alert_chk = ttk.Checkbutton(
            self.options_frame, 
            text="Enable Alerts", 
            variable=self.alert_var
        )
        self.alert_chk.pack(pady=2)

        # Main content frame
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        # Left panel (packet table)
        self.left_panel = ttk.Frame(self.content_frame)
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Packet table frame
        self.table_frame = ttk.LabelFrame(self.left_panel, text="Captured Packets", padding=(5, 5))
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        # TreeView (Table)
        columns = ('no', 'time', 'src', 'dst', 'proto', 'len', 'info')
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show='headings', selectmode='browse')

        # Configure columns
        self.tree.column('no', width=50, anchor=tk.CENTER)
        self.tree.column('time', width=100, anchor=tk.CENTER)
        self.tree.column('src', width=150, anchor=tk.W)
        self.tree.column('dst', width=150, anchor=tk.W)
        self.tree.column('proto', width=80, anchor=tk.CENTER)
        self.tree.column('len', width=80, anchor=tk.CENTER)
        self.tree.column('info', width=300, anchor=tk.W)

        # Configure headings
        self.tree.heading('no', text='No.')
        self.tree.heading('time', text='Time')
        self.tree.heading('src', text='Source IP')
        self.tree.heading('dst', text='Destination IP')
        self.tree.heading('proto', text='Protocol')
        self.tree.heading('len', text='Length')
        self.tree.heading('info', text='Info')

        # Add scrollbar
        yscroll = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=yscroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Right panel (details and visualizations)
        self.right_panel = ttk.Frame(self.content_frame, width=400)
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))

        # Packet details frame
        self.details_frame = ttk.LabelFrame(self.right_panel, text="Packet Details", padding=(10, 5))
        self.details_frame.pack(fill=tk.BOTH, expand=True)

        self.details_text = scrolledtext.ScrolledText(
            self.details_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            height=10,
            padx=5,
            pady=5
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # Visualization frame (only if matplotlib is available)
        if MATPLOTLIB_AVAILABLE:
            self.visualization_frame = ttk.LabelFrame(self.right_panel, text="Protocol Distribution", padding=(10, 5))
            self.visualization_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

            # Create matplotlib figure
            self.figure = plt.Figure(figsize=(5, 4), dpi=100)
            self.ax = self.figure.add_subplot(111)
            self.canvas = FigureCanvasTkAgg(self.figure, self.visualization_frame)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            self.visualization_frame = ttk.LabelFrame(self.right_panel, text="Visualization Not Available", padding=(10, 5))
            self.visualization_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
            ttk.Label(self.visualization_frame, 
                     text="Install matplotlib for visualization\nRun: pip install matplotlib",
                     justify=tk.CENTER).pack(expand=True)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, pady=(10, 0))

        # Bind treeview selection
        self.tree.bind('<<TreeviewSelect>>', self.show_packet_details)

        self.sniffing = False
        self.thread = None

    def toggle_hostname_resolution(self):
        self.hostname_resolution = self.hostname_var.get()
        self.update_status(f"Hostname resolution {'enabled' if self.hostname_resolution else 'disabled'}")

    def packet_callback(self, packet):
        """Process each captured packet and apply filters"""
        if IP in packet:
            # IP filter check
            if self.ip_filter and (packet[IP].src != self.ip_filter and packet[IP].dst != self.ip_filter):
                return

            # Protocol filter check from radio buttons (TCP, UDP, ICMP, or None = all)
            if self.protocol_filter and not self.protocol_filter(packet):
                return

            # Check checkboxes filters: If none checked, no packets show, so skip
            selected_filters = self.get_selected_filters()
            if not selected_filters:
                return

            # Check if the packet matches any of the selected protocol checkboxes
            matched_proto = None
            for proto_name, proto_filter in selected_filters.items():
                if proto_filter(packet):
                    matched_proto = proto_name
                    break

            if not matched_proto:
                return  # Doesn't match selected protocols checkbox

            # Update statistics
            self.protocol_stats[matched_proto] += 1
            
            # Determine if packet is incoming or outgoing (simplified)
            if hasattr(packet[IP], 'src') and self.ip_filter:
                if packet[IP].src == self.ip_filter:
                    self.traffic_stats["outgoing"] += 1
                else:
                    self.traffic_stats["incoming"] += 1

            # Check for suspicious patterns
            if self.alert_var.get():
                self.check_for_alerts(packet, matched_proto)

            # Prepare packet info string
            info = self.get_packet_info(packet, matched_proto)

            # Get source and destination with optional hostname resolution
            src = packet[IP].src
            dst = packet[IP].dst
            if self.hostname_resolution:
                src = f"{src} ({get_hostname(src)})" if src != self.ip_filter else src
                dst = f"{dst} ({get_hostname(dst)})" if dst != self.ip_filter else dst

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            pkt_data = {
                "no": self.packet_counter,
                "time": timestamp,
                "src": src,
                "dst": dst,
                "proto": matched_proto,
                "len": len(packet),
                "info": info,
                "raw": packet
            }
            self.packet_counter += 1
            self.captured_packets.append(pkt_data)
            
            # Insert into GUI
            self.update_packet_table(pkt_data)
            self.update_packet_details(pkt_data)
            if MATPLOTLIB_AVAILABLE:
                self.update_visualization()

    def get_packet_info(self, packet, protocol):
        """Extract protocol-specific information from the packet"""
        info = ""
        
        if protocol == "TCP":
            info = f"TCP {packet[TCP].sport} → {packet[TCP].dport} "
            if packet[TCP].flags:
                flags = []
                if packet[TCP].flags & 0x01: flags.append("FIN")
                if packet[TCP].flags & 0x02: flags.append("SYN")
                if packet[TCP].flags & 0x04: flags.append("RST")
                if packet[TCP].flags & 0x08: flags.append("PSH")
                if packet[TCP].flags & 0x10: flags.append("ACK")
                if packet[TCP].flags & 0x20: flags.append("URG")
                info += "[" + " ".join(flags) + "]"
                
        elif protocol == "UDP":
            info = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
            
        elif protocol == "ICMP":
            info = f"ICMP Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
            
        elif protocol == "DNS" and DNS in packet:
            if packet[DNS].qr == 0:  # DNS query
                if DNSQR in packet:
                    info = f"DNS Query for {packet[DNSQR].qname.decode('utf-8', 'ignore')}"
            else:  # DNS response
                info = "DNS Response"
                
        elif protocol in ["HTTP", "HTTPS"] and TCP in packet and Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', 'ignore')
                if "\r\n" in payload:  # Simple HTTP detection
                    first_line = payload.split('\r\n')[0]
                    info = f"HTTP: {first_line}"
            except:
                info = "HTTP Data"
                
        return info

    def check_for_alerts(self, packet, protocol):
        """Check for suspicious patterns in packets"""
        alerts = []
        
        # TCP SYN scan detection
        if protocol == "TCP" and packet[TCP].flags == 0x02:  # SYN flag only
            alerts.append("Possible SYN scan detected")
            
        # ICMP ping sweep detection
        if protocol == "ICMP" and packet[ICMP].type == 8:  # Echo request
            if self.protocol_stats["ICMP"] > 10:  # More than 10 ICMP packets
                alerts.append("Possible ICMP ping sweep detected")
                
        # DNS tunneling detection
        if protocol == "DNS" and DNS in packet:
            if packet[DNS].qr == 0 and DNSQR in packet:  # DNS query
                query = packet[DNSQR].qname.decode('utf-8', 'ignore')
                if len(query) > 50:  # Unusually long DNS query
                    alerts.append(f"Possible DNS tunneling: long query ({len(query)} chars)")
                    
        # HTTP suspicious requests
        if protocol in ["HTTP", "HTTPS"] and TCP in packet and Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', 'ignore')
                if "HTTP" in payload:
                    if any(method in payload for method in ["POST", "PUT", "DELETE"]):
                        if "admin" in payload.lower() or "login" in payload.lower():
                            alerts.append("Suspicious HTTP request to admin/login page")
            except:
                pass
                
        # Show alerts if any
        if alerts:
            for alert in alerts:
                self.update_status(f"ALERT: {alert}")
                if self.hostname_resolution:
                    src = f"{packet[IP].src} ({get_hostname(packet[IP].src)})"
                else:
                    src = packet[IP].src
                self.details_text.insert(tk.END, f"! ALERT: {alert} from {src}\n", 'alert')
                self.details_text.tag_config('alert', foreground='red')
                self.details_text.see(tk.END)

    def set_ip_filter(self):
        ip = self.ip_entry.get().strip()

        if not ip:
            self.clear_ip_filter()
            return

        if not is_valid_ip(ip):
            messagebox.showerror(
                "Invalid IP",
                "Please enter a valid IPv4 address:\n- Format: XXX.XXX.XXX.XXX\n- Each octet between 0-255\nExample: 192.168.1.1"
            )
            self.ip_entry.focus()
            return

        self.ip_filter = ip
        self.filter_status.config(text=f"Filtering IP: {ip}")
        self.update_status(f"IP filter set to: {ip}")

    def clear_ip_filter(self):
        self.ip_filter = None
        self.ip_entry.delete(0, tk.END)
        self.filter_status.config(text="No IP filter set")
        self.update_status("IP filter cleared")

    def set_protocol_filter(self):
        selected_proto = self.protocol_var.get()
        filter_map = {
            "All": None,
            "TCP": lambda pkt: TCP in pkt,
            "UDP": lambda pkt: UDP in pkt,
            "ICMP": lambda pkt: ICMP in pkt,
        }
        self.protocol_filter = filter_map.get(selected_proto)
        status_msg = (
            "Protocol filter cleared (showing all protocols)"
            if selected_proto == "All"
            else f"Protocol filter set to: {selected_proto}"
        )
        self.update_status(status_msg)

    def get_selected_filters(self):
        """Return protocol filters corresponding to checkboxes selected"""
        return {
            proto: filt
            for proto, filt in protocol_filters.items()
            if self.protocol_vars.get(proto, tk.BooleanVar()).get()
        }

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()

    def update_packet_table(self, pkt):
        self.tree.insert('', tk.END, values=(
            pkt["no"],
            pkt["time"],
            pkt["src"],
            pkt["dst"],
            pkt["proto"],
            pkt["len"],
            pkt["info"]
        ))
        self.update_status(f"Captured {pkt['no']} packets")

    def update_packet_details(self, pkt):
        self.details_text.insert(tk.END,
                                 f"[{pkt['time']}] {pkt['proto']} {pkt['src']} → {pkt['dst']} Len={pkt['len']} {pkt['info']}\n")
        self.details_text.see(tk.END)

    def update_visualization(self):
        """Update the protocol distribution visualization"""
        if not MATPLOTLIB_AVAILABLE or not self.protocol_stats:
            return
            
        # Clear previous plot
        self.ax.clear()
        
        # Prepare data
        labels = list(self.protocol_stats.keys())
        sizes = list(self.protocol_stats.values())
        colors = [protocol_colors.get(proto, protocol_colors["Other"]) for proto in labels]
        
        # Create pie chart
        self.ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        self.ax.axis('equal')  # Equal aspect ratio ensures pie is drawn as a circle
        self.ax.set_title('Protocol Distribution')
        
        # Redraw canvas
        self.canvas.draw()

    def show_packet_details(self, event):
        selected = self.tree.focus()
        if selected:
            item = self.tree.item(selected)
            packet = next((pkt for pkt in self.captured_packets if pkt["no"] == item['values'][0]), None)
            
            if packet:
                details = (
                    f"Packet No.: {packet['no']}\n"
                    f"Time: {packet['time']}\n"
                    f"Source: {packet['src']}\n"
                    f"Destination: {packet['dst']}\n"
                    f"Protocol: {packet['proto']}\n"
                    f"Length: {packet['len']} bytes\n"
                    f"Info: {packet['info']}\n\n"
                    f"Raw Packet Summary:\n{packet['raw'].summary()}"
                )
                self.details_text.delete(1.0, tk.END)
                self.details_text.insert(tk.END, details)

    def show_statistics(self):
        """Show detailed statistics in a new window"""
        if not self.captured_packets:
            messagebox.showinfo("Statistics", "No data available for statistics.")
            return
            
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Network Traffic Statistics")
        stats_window.geometry("600x500")
        
        # Main frame
        main_frame = ttk.Frame(stats_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Notebook for multiple tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Protocol statistics tab
        proto_frame = ttk.Frame(notebook)
        notebook.add(proto_frame, text="Protocols")
        
        # Treeview for protocol stats
        columns = ('protocol', 'count', 'percentage')
        tree = ttk.Treeview(proto_frame, columns=columns, show='headings')
        
        tree.column('protocol', width=150, anchor=tk.W)
        tree.column('count', width=100, anchor=tk.CENTER)
        tree.column('percentage', width=100, anchor=tk.CENTER)
        
        tree.heading('protocol', text='Protocol')
        tree.heading('count', text='Count')
        tree.heading('percentage', text='Percentage')
        
        # Add data
        total = sum(self.protocol_stats.values())
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100 if total > 0 else 0
            tree.insert('', tk.END, values=(proto, count, f"{percentage:.1f}%"))
        
        tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Traffic direction tab
        traffic_frame = ttk.Frame(notebook)
        notebook.add(traffic_frame, text="Traffic Direction")
        
        if MATPLOTLIB_AVAILABLE:
            # Create figure for traffic direction
            fig = plt.Figure(figsize=(5, 4), dpi=100)
            ax = fig.add_subplot(111)
            
            labels = ['Incoming', 'Outgoing']
            sizes = [self.traffic_stats["incoming"], self.traffic_stats["outgoing"]]
            colors = ['#1f77b4', '#ff7f0e']
            
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')
            ax.set_title('Traffic Direction')
            
            canvas = FigureCanvasTkAgg(fig, traffic_frame)
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            canvas.draw()
        else:
            ttk.Label(traffic_frame, 
                     text="Visualization requires matplotlib\nRun: pip install matplotlib",
                     justify=tk.CENTER).pack(expand=True)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.export_btn.config(state="disabled")
            self.clear_btn.config(state="disabled")
            self.analyze_btn.config(state="disabled")
            self.update_status("Sniffing started...")

            # Reset counters and stats for new capture
            self.captured_packets.clear()
            self.packet_counter = 1
            self.protocol_stats.clear()
            self.traffic_stats = {"incoming": 0, "outgoing": 0}
            self.tree.delete(*self.tree.get_children())
            self.details_text.delete(1.0, tk.END)
            if MATPLOTLIB_AVAILABLE:
                self.ax.clear()
                self.canvas.draw()

            self.thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.thread.start()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=False, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.export_btn.config(state="normal")
            self.clear_btn.config(state="normal")
            self.analyze_btn.config(state="normal")
            self.update_status(f"Sniffing stopped. Captured {len(self.captured_packets)} packets.")

    def clear_data(self):
        self.captured_packets.clear()
        self.packet_counter = 1
        self.protocol_stats.clear()
        self.traffic_stats = {"incoming": 0, "outgoing": 0}
        self.tree.delete(*self.tree.get_children())
        self.details_text.delete(1.0, tk.END)
        if MATPLOTLIB_AVAILABLE:
            self.ax.clear()
            self.canvas.draw()
        self.update_status("Data cleared. Ready to start new capture.")

    def export_to_csv(self):
        if not self.captured_packets:
            self.update_status("No data to export")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save captured packets as"
        )

        if file_path:
            try:
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["No.", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Info"])
                    for pkt in self.captured_packets:
                        # Remove hostname resolution for CSV export
                        src = pkt["src"].split(" ")[0] if "(" in pkt["src"] else pkt["src"]
                        dst = pkt["dst"].split(" ")[0] if "(" in pkt["dst"] else pkt["dst"]
                        writer.writerow([
                            pkt["no"],
                            pkt["time"],
                            src,
                            dst,
                            pkt["proto"],
                            pkt["len"],
                            pkt["info"]
                        ])
                self.update_status(f"Data exported successfully to {file_path}")
            except Exception as e:
                self.update_status(f"Error exporting data: {str(e)}")
                messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()