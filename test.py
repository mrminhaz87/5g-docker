from scapy.all import sniff, wrpcap
import time

def packet_callback(packet):
    print(f"Captured packet: {packet.summary()}")
    return packet

def capture_packets(duration, output_file):
    print(f"Starting packet capture for {duration} seconds. Press Ctrl+C to stop early.")
    try:
        packets = sniff(timeout=duration, prn=packet_callback)
        wrpcap(output_file, packets)
        print(f"Capture complete. Packets saved to {output_file}")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        wrpcap(output_file, packets)
        print(f"Packets saved to {output_file}")

if __name__ == "__main__":
    duration = 60  # Capture for 60 seconds
    output_file = "captured_packets.pcap"
    capture_packets(duration, output_file)
