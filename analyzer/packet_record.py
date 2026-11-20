# Katarina Mantay -- 11/20/2026
from scapy.all import IP, TCP, UDP, ICMP

# holds info about one packet
# holds : time it was captured, src/dest ips + ports, protocol (TCP/UDP/ICMP/Other), size of packet, summary from scapy, OG packet
class PacketRecord:
    def __init__(self, timestamp, src_ip, dest_ip, src_port, dest_port, protocol, length, info, raw_scapy_packet):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.length = length
        self.info = info
        self.raw_scapy_packet = raw_scapy_packet

def packet_to_record(packet):

    # defaults incase they arent found
    src_ip = "-"
    dest_ip = "-"
    src_port = "-"
    dest_port = "-"
    protocol = "Other"

    timestamp = float(packet.time)
    length = len(packet)
    info = packet.summary()

    # checks for packet IP
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst

    # checks packet protocol (icmp doesnt use ports)
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = str(packet[TCP].sport)
        dest_port = str(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = str(packet[UDP].sport)
        dest_port = str(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return PacketRecord(timestamp, src_ip, dest_ip, src_port, dest_port, protocol, length, info, packet)