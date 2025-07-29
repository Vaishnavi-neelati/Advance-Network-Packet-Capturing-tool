import pyshark
import threading
import datetime
import tkinter as tk
from tkinter import ttk, messagebox

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer (Wireshark + PyShark)")
        self.capture = None
        self.capture_thread = None
        self.running = False

        # GUI Elements
        self.interface_label = ttk.Label(root, text="Select Interface:")
        self.interface_label.grid(row=0, column=0, padx=5, pady=5)

        self.interface_combo = ttk.Combobox(root, width=30)
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5)

        self.filter_label = ttk.Label(root, text="Protocol Filter (optional):")
        self.filter_label.grid(row=1, column=0, padx=5, pady=5)

        self.filter_entry = ttk.Entry(root)
        self.filter_entry.grid(row=1, column=1, padx=5, pady=5)

        self.start_button = ttk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=2, column=0, padx=5, pady=10)

        self.stop_button = ttk.Button(root, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=1, padx=5, pady=10)

        self.output_box = tk.Text(root, height=20, width=80)
        self.output_box.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.load_interfaces()

    def load_interfaces(self):
        try:
            interfaces = pyshark.LiveCapture().interfaces
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.current(0)
        except Exception as e:
            messagebox.showerror("Error", f"Could not list interfaces:\n{str(e)}")

    def start_capture(self):
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        protocol_filter = self.filter_entry.get().strip()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_file = f"capture_{timestamp}.pcap"

        self.capture = pyshark.LiveCapture(interface=interface, output_file=self.output_file,
                                           display_filter=protocol_filter if protocol_filter else None)

        self.capture_thread = threading.Thread(target=self.sniff_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def sniff_packets(self):
        try:
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                try:
                    src = packet.ip.src
                    dst = packet.ip.dst
                    proto = packet.transport_layer or "Other"
                    line = f"{proto} | {src} -> {dst}"
                except AttributeError:
                    line = "Non-IP Packet"

                self.output_box.insert(tk.END, line + "\n")
                self.output_box.see(tk.END)
        except Exception as e:
            self.output_box.insert(tk.END, f"\nError: {e}\n")

    def stop_capture(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if self.capture:
            self.capture.close()

        messagebox.showinfo("Capture Saved", f"Packet capture saved to:\n{self.output_file}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
