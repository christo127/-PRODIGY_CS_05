from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        
        # Check if the packet is TCP, UDP, or ICMP and print details
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Port: {tcp_layer.sport} -> {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Port: {udp_layer.sport} -> {udp_layer.dport}")
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"ICMP Type: {icmp_layer.type}")
        
        # Print payload if it exists
        if packet.payload:
            print(f"Payload: {bytes(packet.payload)}")

def main():
    # Start sniffing, apply the packet_callback to each captured packet
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
