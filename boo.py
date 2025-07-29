import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import csv
from datetime import datetime

captured_packets = []
packet_counter = 1

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

def packet_callback(packet):
    global packet_counter
    if IP in packet:
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
        self.root.title("Dark Packet Sniffer")
        self.root.geometry("1100x750")
        self.root.minsize(900, 650)
        
        # Configure dark theme
        self.style = ttk.Style()
        self.style.theme_use('alt')
        
        # Color scheme
        self.bg_color = '#2d2d2d'
        self.fg_color = '#e0e0e0'
        self.accent_color = '#4a6fa5'
        self.table_bg = '#3d3d3d'
        self.table_fg = '#ffffff'
        self.table_sel = '#4a6fa5'
        
        # Configure styles
        self.style.configure('.', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('TButton', background=self.bg_color, foreground=self.fg_color, 
                           bordercolor=self.accent_color, focuscolor=self.bg_color)
        self.style.map('TButton', background=[('active', self.accent_color)])
        self.style.configure('Treeview', background=self.table_bg, foreground=self.table_fg,
                           fieldbackground=self.table_bg, rowheight=25)
        self.style.configure('Treeview.Heading', background=self.accent_color, 
                           foreground='white', font=('Arial', 10, 'bold'))
        self.style.map('Treeview', background=[('selected', self.table_sel)])
        self.style.configure('TLabelframe', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.fg_color)
        
        # Main container
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header frame
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        self.title_label = ttk.Label(self.header_frame, text="DARK PACKET SNIFFER", 
                                   font=('Arial', 14, 'bold'), foreground=self.accent_color)
        self.title_label.pack(side=tk.LEFT)
        
        # Stats label
        self.stats_var = tk.StringVar()
        self.stats_var.set("Packets: 0")
        self.stats_label = ttk.Label(self.header_frame, textvariable=self.stats_var, 
                                   font=('Arial', 10), foreground='#a0a0a0')
        self.stats_label.pack(side=tk.RIGHT)
        
        # Control panel frame
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding=(15, 10))
        self.control_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Left control panel (filters)
        self.filter_frame = ttk.Frame(self.control_frame)
        self.filter_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Protocol filter label
        ttk.Label(self.filter_frame, text="Protocol Filters:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        # Protocol checkboxes in a grid
        self.protocol_vars = {}
        self.check_frame = ttk.Frame(self.filter_frame)
        self.check_frame.pack(fill=tk.X, pady=(5, 0))
        
        for i, proto in enumerate(protocol_filters):
            self.protocol_vars[proto] = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(self.check_frame, text=proto, variable=self.protocol_vars[proto],
                                 style='Toolbutton')
            chk.grid(row=i//4, column=i%4, sticky="w", padx=5, pady=2)
        
        # Right control panel (buttons)
        self.button_frame = ttk.Frame(self.control_frame)
        self.button_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Control buttons with icons (using text symbols as icons)
        btn_style = {'style': 'TButton', 'width': 12}
        self.start_btn = ttk.Button(self.button_frame, text="▶ Start", 
                                  command=self.start_sniffing, **btn_style)
        self.start_btn.pack(fill=tk.X, pady=3)
        
        self.stop_btn = ttk.Button(self.button_frame, text="■ Stop", 
                                 command=self.stop_sniffing, state="disabled", **btn_style)
        self.stop_btn.pack(fill=tk.X, pady=3)
        
        self.export_btn = ttk.Button(self.button_frame, text="⬇ Export", 
                                   command=self.export_to_csv, **btn_style)
        self.export_btn.pack(fill=tk.X, pady=3)
        
        self.clear_btn = ttk.Button(self.button_frame, text="✖ Clear", 
                                  command=self.clear_data, **btn_style)
        self.clear_btn.pack(fill=tk.X, pady=3)
        
        # Packet display area
        self.display_frame = ttk.Frame(self.main_frame)
        self.display_frame.pack(fill=tk.BOTH, expand=True)
        
        # Packet table frame
        self.table_frame = ttk.LabelFrame(self.display_frame, text="Packet List", padding=(5, 5))
        self.table_frame.pack(fill=tk.BOTH, expand=True)
        
        # TreeView (Table)
        columns = ('no', 'time', 'src', 'dst', 'proto', 'len', 'info')
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show='headings', selectmode='browse')
        
        # Configure columns
        col_widths = {'no': 50, 'time': 120, 'src': 180, 'dst': 180, 'proto': 80, 'len': 70, 'info': 350}
        for col, width in col_widths.items():
            self.tree.column(col, width=width, anchor=tk.CENTER if col in ['no', 'proto', 'len'] else tk.W)
            self.tree.heading(col, text=col.capitalize())
        
        # Add scrollbars
        yscroll = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(self.table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=yscroll.set, xscroll=xscroll.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        yscroll.grid(row=0, column=1, sticky='ns')
        xscroll.grid(row=1, column=0, sticky='ew')
        
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)
        
        # Packet details frame
        self.details_frame = ttk.LabelFrame(self.display_frame, text="Packet Details", padding=(10, 5))
        self.details_frame.pack(fill=tk.BOTH, pady=(10, 0))
        
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame, 
            wrap=tk.WORD, 
            font=('Consolas', 10), 
            height=8,
            padx=5,
            pady=5,
            bg='#3d3d3d',
            fg='#ffffff',
            insertbackground='white',
            selectbackground=self.accent_color
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, 
                                  relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Bind treeview selection
        self.tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        
        self.sniffing = False
        self.thread = None
    
    def update_status(self, message):
        self.status_var.set(message)
        self.stats_var.set(f"Packets: {len(captured_packets)}")
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
        self.update_status(f"Packet #{pkt['no']} captured")
    
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
                f"Time:       {item['values'][1]}\n"
                f"Source:     {item['values'][2]}\n"
                f"Destination:{item['values'][3]}\n"
                f"Protocol:   {item['values'][4]}\n"
                f"Length:     {item['values'][5]} bytes\n"
                f"Info:       {item['values'][6]}\n"
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
