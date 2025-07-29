import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import csv
from datetime import datetime
import re

captured_packets = []
packet_counter = 1
ip_filter = None

# Protocol filters using lambda functions
protocol_filters = {
    "TCP": lambda pkt: TCP in pkt,
    "UDP": lambda pkt: UDP in pkt,
    "ICMP": lambda pkt: ICMP in pkt,
    "FTP": lambda pkt: TCP in pkt and (pkt[TCP].sport == 21 or pkt[TCP].dport == 21),
    "HTTP": lambda pkt: TCP in pkt and (pkt[TCP].sport == 80 or pkt[TCP].dport == 80),
    "HTTPS": lambda pkt: TCP in pkt and (pkt[TCP].sport == 443 or pkt[TCP].dport == 443),
    "DNS": lambda pkt: UDP in pkt and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53),
}

def is_valid_ip(ip):
    """Check if the IP address is valid"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(0 <= int(num) <= 255 for num in ip.split('.'))
    return False

def packet_callback(packet):
    global packet_counter
    if IP in packet:
        # Check if IP filter is set and packet matches
        if ip_filter and (packet[IP].src != ip_filter and packet[IP].dst != ip_filter):
            return
            
        for proto_name, proto_filter in app.get_selected_filters().items():
            if proto_filter(packet):
                info = ""
                if TCP in packet:
                    info = f"TCP Port {packet[TCP].sport} → {packet[TCP].dport}"
                elif UDP in packet:
                    info = f"UDP Port {packet[UDP].sport} → {packet[UDP].dport}"
                elif ICMP in packet:
                    info = f"ICMP Type {packet[ICMP].type}"

                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                pkt_data = {
                    "no": packet_counter,
                    "time": timestamp,
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "proto": proto_name,
                    "len": len(packet),
                    "info": info
                }
                packet_counter += 1
                captured_packets.append(pkt_data)
                app.update_packet_table(pkt_data)
                app.update_packet_details(pkt_data)
                break

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Packet Sniffer")
        self.root.geometry("1100x750")
        self.root.minsize(900, 650)
        
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
        
        # Status label
        self.filter_status = ttk.Label(self.ip_filter_frame, text="No IP filter set")
        self.filter_status.pack(side=tk.RIGHT, padx=10)
        
        # Control panel frame
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding=(10, 5))
        self.control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Protocol filter frame
        self.filter_frame = ttk.LabelFrame(self.control_frame, text="Protocol Filters", padding=(10, 5))
        self.filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        # Protocol checkboxes
        self.protocol_vars = {}
        for i, proto in enumerate(protocol_filters):
            self.protocol_vars[proto] = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(self.filter_frame, text=proto, variable=self.protocol_vars[proto])
            chk.grid(row=i//4, column=i%4, sticky="w", padx=5, pady=2)
        
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
        
        # Packet table frame
        self.table_frame = ttk.LabelFrame(self.main_frame, text="Captured Packets", padding=(5, 5))
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
        
        # Packet details frame
        self.details_frame = ttk.LabelFrame(self.main_frame, text="Packet Details", padding=(10, 5))
        self.details_frame.pack(fill=tk.BOTH, pady=(10, 0))
        
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame, 
            wrap=tk.WORD, 
            font=('Consolas', 10), 
            height=8,
            padx=5,
            pady=5
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Bind treeview selection
        self.tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        
        self.sniffing = False
        self.thread = None
    
    def set_ip_filter(self):
        global ip_filter
        ip = self.ip_entry.get().strip()
        if not ip:
            self.clear_ip_filter()
            return
            
        if is_valid_ip(ip):
            ip_filter = ip
            self.filter_status.config(text=f"Filtering IP: {ip}")
            self.update_status(f"IP filter set to: {ip}")
        else:
            messagebox.showerror("Invalid IP", "Please enter a valid IP address (e.g., 192.168.1.1)")
    
    def clear_ip_filter(self):
        global ip_filter
        ip_filter = None
        self.ip_entry.delete(0, tk.END)
        self.filter_status.config(text="No IP filter set")
        self.update_status("IP filter cleared")
    
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
    
    def show_packet_details(self, event):
        selected = self.tree.focus()
        if selected:
            item = self.tree.item(selected)
            details = (
                f"Packet No.: {item['values'][0]}\n"
                f"Time: {item['values'][1]}\n"
                f"Source: {item['values'][2]}\n"
                f"Destination: {item['values'][3]}\n"
                f"Protocol: {item['values'][4]}\n"
                f"Length: {item['values'][5]} bytes\n"
                f"Info: {item['values'][6]}\n"
            )
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details)
    
    def get_selected_filters(self):
        return {proto: filt for proto, filt in protocol_filters.items() if self.protocol_vars[proto].get()}
    
    def start_sniffing(self):
        global packet_counter
        if not self.sniffing:
            self.sniffing = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.export_btn.config(state="disabled")
            self.clear_btn.config(state="disabled")
            self.update_status("Sniffing started...")
            
            self.thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.thread.start()
    
    def sniff_packets(self):
        sniff(prn=packet_callback, store=False, stop_filter=lambda x: not self.sniffing)
    
    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.export_btn.config(state="normal")
            self.clear_btn.config(state="normal")
            self.update_status(f"Sniffing stopped. Captured {len(captured_packets)} packets.")
    
    def clear_data(self):
        global captured_packets, packet_counter
        captured_packets = []
        packet_counter = 1
        self.tree.delete(*self.tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.update_status("Data cleared. Ready to start new capture.")
    
    def export_to_csv(self):
        if not captured_packets:
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
                    for pkt in captured_packets:
                        writer.writerow([
                            pkt["no"], 
                            pkt["time"], 
                            pkt["src"], 
                            pkt["dst"], 
                            pkt["proto"], 
                            pkt["len"], 
                            pkt["info"]
                        ])
                self.update_status(f"Data exported successfully to {file_path}")
            except Exception as e:
                self.update_status(f"Error exporting data: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
