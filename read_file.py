from scapy.all import *

# Read the pcap file
packets = rdpcap("multiple_attempts.pcap")

# Initialize handshake counter
handshake_count = 0

# Loop through the packets in groups of three
for i in range(0, len(packets), 3):
    # Extract three packets for each iteration
    syn_pkt = packets[i]
    syn_ack_pkt = packets[i+1]
    ack_pkt = packets[i+2]

    # Check if all three packets are present and form a complete handshake
    if syn_pkt.haslayer(TCP) and syn_ack_pkt.haslayer(TCP) and ack_pkt.haslayer(TCP):
        if syn_pkt[TCP].flags == "S" and syn_ack_pkt[TCP].flags == "SA" and ack_pkt[TCP].flags == "A":
            handshake_count += 1

print("Total TCP three-way handshakes:", handshake_count)
