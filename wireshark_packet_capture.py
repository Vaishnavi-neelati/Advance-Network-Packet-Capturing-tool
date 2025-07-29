import pyshark
import datetime
import os

def list_interfaces():
    print("Available Network Interfaces:")
    interfaces = pyshark.LiveCapture().interfaces
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}. {iface}")
    return interfaces

def select_interface(interfaces):
    index = int(input("Enter the number of the interface to capture on: ")) - 1
    return interfaces[index]

def start_capture(interface, packet_count=20, save_pcap=True):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"packet_capture_{timestamp}.pcap" if save_pcap else None

    print(f"\nStarting capture on interface: {interface}")
    print(f"Capturing {packet_count} packets...\n")

    # Setup live capture using TShark (via PyShark)
    capture = pyshark.LiveCapture(interface=interface, output_file=output_filename)

    try:
        for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count)):
            print(f"Packet {i + 1}")
            try:
                print(f"  Time       : {packet.sniff_time}")
                print(f"  Source IP  : {packet.ip.src}")
                print(f"  Dest IP    : {packet.ip.dst}")
                print(f"  Protocol   : {packet.transport_layer}")
                print(f"  Length     : {packet.length}")
            except AttributeError:
                print("  Non-IP Packet or Incomplete Packet")
            print("-" * 50)

        if save_pcap:
            print(f"\n✅ Packets saved to: {output_filename}")

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
        if save_pcap and os.path.exists(output_filename):
            print(f"Partial capture saved to: {output_filename}")

if __name__ == "__main__":
    print("=== Advanced Network Packet Capture Tool (Wireshark Backend) ===")
    interfaces = list_interfaces()
    selected_interface = select_interface(interfaces)

    try:
        num_packets = int(input("Enter number of packets to capture: "))
    except ValueError:
        num_packets = 20

    start_capture(selected_interface, packet_count=num_packets, save_pcap=True)
