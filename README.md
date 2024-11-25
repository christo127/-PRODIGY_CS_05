# Python Packet Sniffer

A simple packet sniffer tool written in Python using the `scapy` library. This script captures and analyzes network packets, displaying information such as source and destination IP addresses, protocols, and payload data.

## Features

- Captures network packets in real-time.
- Displays source and destination IP addresses.
- Identifies the protocol (TCP, UDP, ICMP).
- Displays payload data if available.

## Requirements

- Python 3.x
- `scapy` library

## Installation

1. **Clone the repository:**

    ```bash
    https://github.com/MuhammedFasilkk/PRODIGY_CS_05.git
    ```

2. **Navigate to the project directory:**

    ```bash
    cd packet-sniffer
    ```

3. **Install the required dependencies:**

    ```bash
    pip install scapy
    ```

## Usage

1. **Run the packet sniffer script:**

    ```bash
    python packet_sniffer.py
    ```

2. The script will start capturing packets and display the information in the console.

## Important Notice

**This packet sniffer is for educational purposes only.** Ensure that you have explicit permission to capture and analyze network traffic on any network you use this tool on. Unauthorized use of packet sniffers is illegal and unethical.

## Ethical Considerations

- **Obtain Consent:** Always get permission from the network owner or administrator before running this tool.
- **Legal Compliance:** Ensure that your use of this script complies with local laws and regulations.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Contributing

If you'd like to contribute to this project, please fork the repository and use a feature branch. Pull requests are warmly welcome.

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
