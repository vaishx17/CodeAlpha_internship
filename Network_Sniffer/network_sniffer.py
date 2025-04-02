from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime

seen_packets = set()  # Store seen packets to prevent duplicates

def packet_callback(packet):
    if IP in packet:  # Process only IP packets
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Determine protocol name
        protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "Unknown Protocol")

        # Extract port numbers only if the layer exists
        src_port, dst_port = "N/A", "N/A"

        if protocol == 6 and TCP in packet:  # TCP packet
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17 and UDP in packet:  # UDP packet
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Create a unique hash for this packet
        packet_hash = f"{src_ip}:{src_port}->{dst_ip}:{dst_port} {protocol_name}"
        
        # Avoid duplicate logs
        if packet_hash in seen_packets:
            return
        seen_packets.add(packet_hash)

        # Packet log format
        log_entry = f"""
        -----------------------------------
        Timestamp: {timestamp}
        Protocol: {protocol_name}
        Source IP: {src_ip}  Port: {src_port}
        Destination IP: {dst_ip}  Port: {dst_port}
        -----------------------------------
        """
        
        print(log_entry)

        # Save to log file
        with open("sniffer_log.txt", "a") as log_file:
            log_file.write(log_entry + "\n")

# Start sniffing
print("Starting packet sniffing...")
sniff(prn=packet_callback, store=False)
print("Sniffer stopped.")
