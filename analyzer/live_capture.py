# TODO: kulsum - live capture thread

from scapy.all import AsyncSniffer
from analyzer.packet_table import PacketTable

# create a queue of all raw packets then send them to packet table to be added
# multithreading with a queue to prevent packet loss

def start_live_capture():
    # interface = wifi, packet_callback = add_raw_packet
    sniffer = AsyncSniffer(iface="wifi", prn=packet_callback)
    sniffer.start()
    return sniffer

def stop_live_capture(sniffer):
    sniffer.stop()

# todo: create packet_callback queue w multithreading
def packet_callback(raw_packet):
    # add raw packet to packet table
    packet_table = PacketTable()
    packet_table.add_raw_packet(raw_packet)