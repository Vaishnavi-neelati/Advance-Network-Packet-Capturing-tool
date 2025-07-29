import threading
from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk
from tkinter import ttk, filedialog
import csv

captured_packets = []

def packet_callback(packet):
    if IP in packet:
        proto = ""
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        else:
            proto = "Other"

        pkt_data = {
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": proto,
            "len": len(packet)
        }
        captured_packets.append(pkt_data)
        app.update_packet_table(pkt_data)

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Packet Sniffer")

        self.frame = ttk.Frame(root, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        self.start_btn = ttk.Button(self.frame, text="Start Capture", command=self.start_sniffing)
        self.start_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = ttk.Button(self.frame, text="Stop Capture", command=self.stop_sniffing, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=5)

        self.export_btn = ttk.Button(self.frame, text="Export to CSV", command=self.export_to_csv)
        self.export_btn.grid(row=0, column=2, padx=5)

        self.tree = ttk.Treeview(self.frame, columns=('src', 'dst', 'proto', 'len'), show='headings')
        self.tree.heading('src', text='Source IP')
        self.tree.heading('dst', text='Destination IP')
        self.tree.heading('proto', text='Protocol')
        self.tree.heading('len', text='Length')
        self.tree.grid(row=1, column=0, columnspan=3, pady=10)

        self.sniffing = False

    def update_packet_table(self, pkt):
        self.tree.insert('', tk.END, values=(pkt["src"], pkt["dst"], pkt["proto"], pkt["len"]))

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
                writer.writerow(["Source IP", "Destination IP", "Protocol", "Length"])
                for pkt in captured_packets:
                    writer.writerow([pkt["src"], pkt["dst"], pkt["proto"], pkt["len"]])

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
