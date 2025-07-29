# Advance-Network-Packet-Capturing-tool

# 📡 Network Packet Sniffer – Dora Project

This project is a **GUI-based Network Packet Sniffer** built with **Python**, integrating tools like **Scapy**, **TShark**, and **Tkinter**. It allows users to capture, analyze, and export live network traffic in real time with a simple graphical interface.

## 🧰 Features

- Live packet capturing from network interfaces
- Protocol-based packet filtering (TCP, UDP, ICMP, etc.)
- GUI dashboard for easy interaction (using `Tkinter`)
- Packet data export to CSV (`packet_sniffer.csv`)
- Modular scripts for clean structure and debugging

## 📁 Project Structure

| File | Description |
|------|-------------|
| `gui_wireshark_sniffer.py` | Main GUI for live capturing using TShark |
| `packet_sniffer.py` | Core logic for packet sniffing |
| `wireshark_packet_capture.py` | TShark-based backend logic |
| `boo.py`, `nikki.py`, `shin.py`, etc. | Helper/utility scripts |
| `packet_sniffer.csv` | Exported packet logs |
| `nobi.md` | Developer notes or instructions |

## 🔧 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/dora-packet-sniffer.git
   cd dora-packet-sniffer/dora
   ```

2. Install required Python packages:
   ```bash
   pip install scapy
   ```

3. Ensure the following are installed and properly configured:
   - [Wireshark](https://www.wireshark.org/) (with TShark CLI added to PATH)
   - [Npcap](https://nmap.org/npcap/) (for Windows packet capturing)

## 🚀 Usage

```bash
python gui_wireshark_sniffer.py
```

- Choose a network interface.
- Start capturing packets.
- View protocol, IPs, and data in a structured table.
- Export data for further analysis.

## 📦 Exported Data

All captured packets are stored in `packet_sniffer.csv` for offline processing.

## 📜 License

This project is for educational and research purposes only.

---

> Built with ❤️ using Python, TShark, and Tkinter.
