# Network Packet Analyzer

This tool is a Python-based network packet analyzer developed using the Scapy library, designed to capture and analyze network traffic in real-time. It focuses on IP-based packets and provides insights into network protocols like TCP, UDP, and ICMP.

### **Key Features** 📋:  
1. **Real-Time Packet Capture** 🕵️‍♂️:  
   - Monitors live network traffic and captures IP-based packets.  

2. **Protocol Identification** 🔍:  
   - Recognizes key protocols: **TCP**, **UDP**, and **ICMP**.  

3. **Detailed Packet Insights** 📊:  
   - Displays:  
     - **Source and Destination IPs**  
     - **Protocol Type**  
     - **Payload Data** for TCP/UDP packets (if available).  

---

### **How It Works** ⚙️:  
1. **Packet Sniffing**:  
   - Uses the **Scapy library** to sniff real-time network traffic.  
   - Filters traffic to focus on IP-based packets.  

2. **Packet Analysis**:  
   - For each captured packet:  
     - Extracts the **source and destination IP addresses**.  
     - Identifies the **protocol type** (e.g., TCP, UDP, ICMP).  
     - Retrieves **payload data** for TCP/UDP packets, if available.  

3. **Customizable Interface**:  
   - Allows specifying the network interface (e.g., `eth0`, `wlan0`) for targeted packet capture.  

---

### **Technologies Used** 🛠️:  
- **Python** 🐍: For building the packet analyzer.  
- **Scapy** 🛡️: A powerful Python library for packet sniffing and manipulation.  

---

This tool is a lightweight yet powerful solution for **network traffic analysis**, making it useful for **network security research** and understanding real-time traffic patterns. Looking forward to applying these concepts in more advanced projects! 🚀

---

### **Code**  

Here is the Python code for the Network Packet Analyzer:
```

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
