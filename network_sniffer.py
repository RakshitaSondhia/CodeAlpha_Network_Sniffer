# Import required libraries
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Packet analysis function
def packet_callback(packet):
    # Check if packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Check if the packet is TCP or UDP
        if TCP in packet:
            proto = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            proto = 'Other'
            src_port = None
            dst_port = None

        # Print packet details
        print(f'[+] {ip_src}:{src_port} -> {ip_dst}:{dst_port} ({proto})')

# Start sniffing
def start_sniffing(interface):
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == '__main__':
    # Specify the network interface to sniff (for example 'eth0', 'Wi-Fi' or 'wlan0')
    interface = input("Enter network interface to sniff (e.g., eth0, wlan0): ")
    start_sniffing(interface)
