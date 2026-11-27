from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import NoPayload


def packet_layers(record):
    layers = []
    layer = record.raw_scapy_packet

    while layer is not None and not isinstance(layer, NoPayload):
        if isinstance(layer, Ether):
            name = "Ethernet"
            fields = [
                ("Source MAC", layer.src),
                ("Destination MAC", layer.dst),
                ("EtherType", f"0x{layer.type:04x}"),
            ]
        elif isinstance(layer, IP):
            name = "IP"
            fields = [
                ("Source IP", layer.src),
                ("Destination IP", layer.dst),
                ("Time to live", layer.ttl),
                ("Protocol number", layer.proto),
            ]
        elif isinstance(layer, TCP):
            name = "TCP"
            fields = [
                ("Source port", layer.sport),
                ("Destination port", layer.dport),
                ("Flags", layer.flags),
                ("Sequence number", layer.seq),
                ("Acknowledgment number", layer.ack),
            ]
        elif isinstance(layer, UDP):
            name = "UDP"
            fields = [
                ("Source port", layer.sport),
                ("Destination port", layer.dport),
                ("Length", layer.len),
            ]
        elif isinstance(layer, ICMP):
            name = "ICMP"
            fields = [("Type", layer.type), ("Code", layer.code)]
        else:
            name = "Other"
            fields = [("Layer", layer.name)]

        display_fields = [
            (label, "-" if value is None else str(value))
            for label, value in fields
        ]
        layers.append((name, display_fields))
        layer = layer.payload

    return layers or [("Other", [("Summary", record.info or "-")])]