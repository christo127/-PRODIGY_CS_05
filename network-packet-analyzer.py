from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"\nPacket Captured:")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        
        # Display protocol type
        if proto == 6 and TCP in packet:
            print("Protocol: TCP")
            # Extract TCP payload data, if any
            if packet[TCP].payload:
                print(f"Payload: {bytes(packet[TCP].payload)}")
        elif proto == 17 and UDP in packet:
            print("Protocol: UDP")
            # Extract UDP payload data, if any
            if packet[UDP].payload:
                print(f"Payload: {bytes(packet[UDP].payload)}")
        elif proto == 1 and ICMP in packet:
            print("Protocol: ICMP")
        else:
            print("Protocol: Other")

# Start sniffing packets on the network interface
# Use iface="YOUR_INTERFACE" to specify an interface (e.g., "eth0", "wlan0") if needed
sniff(filter="ip", prn=packet_callback, store=False)
