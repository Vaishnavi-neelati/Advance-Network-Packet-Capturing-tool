import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk, filedialog
import csv

captured_packets = []
packet_counter = 1  # For 'No.' column

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

                pkt_data = {
                    "no": packet_counter,
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "proto": proto_name,
                    "len": len(packet),
                    "info": info
                }
                packet_counter += 1
                captured_packets.append(pkt_data)
                app.update_packet_table(pkt_data)
                break

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Packet Sniffer with Protocol Filter")

        self.frame = ttk.Frame(root, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        # Protocol Filter Checkboxes
        self.protocol_vars = {}
        row = 0
        col = 0
        for i, proto in enumerate(protocol_filters):
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(self.frame, text=proto, variable=var)
            chk.grid(row=row, column=col, sticky="w", padx=5)
            self.protocol_vars[proto] = var
            row += 1
            if row > 3:
                row = 0
                col += 1

        # Buttons
        self.start_btn = ttk.Button(self.frame, text="Start Capture", command=self.start_sniffing)
        self.start_btn.grid(row=5, column=0, padx=5, pady=10)

        self.stop_btn = ttk.Button(self.frame, text="Stop Capture", command=self.stop_sniffing, state="disabled")
        self.stop_btn.grid(row=5, column=1, padx=5)

        self.export_btn = ttk.Button(self.frame, text="Export to CSV", command=self.export_to_csv)
        self.export_btn.grid(row=5, column=2, padx=5)

        # TreeView (Table)
        columns = ('no', 'src', 'dst', 'proto', 'len', 'info')
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', height=15)
        self.tree.heading('no', text='No.')
        self.tree.heading('src', text='Source IP')
        self.tree.heading('dst', text='Destination IP')
        self.tree.heading('proto', text='Protocol')
        self.tree.heading('len', text='Length')
        self.tree.heading('info', text='Info')
        self.tree.grid(row=6, column=0, columnspan=3, pady=10)

        self.sniffing = False

    def update_packet_table(self, pkt):
        self.tree.insert('', tk.END, values=(pkt["no"], pkt["src"], pkt["dst"], pkt["proto"], pkt["len"], pkt["info"]))

    def get_selected_filters(self):
        return {proto: filt for proto, filt in protocol_filters.items() if self.protocol_vars[proto].get()}

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.thread = threading.Thread(target=self.sniff_packets)
        self.thread.start()

    def sniff_packets(self):
        sniff(prn=packet_callback, store=False, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["No.", "Source IP", "Destination IP", "Protocol", "Length", "Info"])
                for pkt in captured_packets:
                    writer.writerow([pkt["no"], pkt["src"], pkt["dst"], pkt["proto"], pkt["len"], pkt["info"]])

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
