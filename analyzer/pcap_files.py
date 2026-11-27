import csv
import os
from pathlib import Path
import struct
import tempfile

from scapy.all import PcapWriter, conf, rdpcap


CSV_FIELDS = (
    "timestamp", "src_ip", "src_port", "dest_ip", "dest_port",
    "protocol", "length", "info",
)


class CaptureFileError(Exception):
    """A capture could not be read or exported; safe to display in the GUI."""


def _validate_pcap(stream):
    # Scapy can silently return partial captures. Reject truncated files before
    # replacing the current table. Support microsecond/nanosecond classic PCAP.
    header = stream.read(24)
    byte_orders = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }
    if len(header) != 24 or header[:4] not in byte_orders:
        raise ValueError("Choose a classic .pcap file (PCAPNG is not supported).")
    order = byte_orders[header[:4]]
    major, minor, _, _, snaplen, _ = struct.unpack(order + "HHiIII", header[4:])
    if (major, minor) != (2, 4) or snaplen == 0:
        raise ValueError("The PCAP header is invalid or uses an unsupported version.")
    file_size = os.fstat(stream.fileno()).st_size
    while True:
        packet_header = stream.read(16)
        if not packet_header:
            break
        if len(packet_header) != 16:
            raise ValueError("The PCAP contains a truncated packet header.")
        _, _, captured_length, wire_length = struct.unpack(order + "IIII", packet_header)
        if captured_length > snaplen or captured_length > wire_length:
            raise ValueError("The PCAP contains invalid packet lengths.")
        if captured_length > file_size - stream.tell():
            raise ValueError("The PCAP contains truncated packet data.")
        stream.seek(captured_length, os.SEEK_CUR)
    stream.seek(0)


def read_pcap(path):
    """Return a list of raw Scapy packets, or raise CaptureFileError."""
    try:
        with open(path, "rb") as stream:
            _validate_pcap(stream)
            return list(rdpcap(stream))
    except Exception as error:
        raise CaptureFileError(f"Could not open PCAP: {error}") from error


def _atomic_export(path, write):
    # Replace the destination only after a successful write and close.
    destination = Path(path)
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".packet-export-", dir=destination.parent)
        temporary = Path(name)
        os.close(descriptor)
        write(temporary)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def export_pcap(path, records):
    """Export the supplied records' original packets, preserving timestamps."""
    try:
        packets = [record.raw_scapy_packet for record in records]
        linktypes = {conf.l2types.layer2num[type(packet)] for packet in packets}
        if len(linktypes) > 1:
            raise ValueError("Packets use different link types; export them separately.")
        linktype = next(iter(linktypes), 1)  # Empty captures use Ethernet.

        def write(temporary):
            with PcapWriter(str(temporary), linktype=linktype, nano=True) as writer:
                writer.write_header(packets[0] if packets else None)
                for packet in packets:
                    writer.write(packet)

        _atomic_export(path, write)
    except Exception as error:
        raise CaptureFileError(f"Could not export PCAP: {error}") from error


def export_csv(path, records):
    """Export record fields using the column order agreed in the README."""
    try:
        def write(temporary):
            with open(temporary, "w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(CSV_FIELDS)
                for record in records:
                    writer.writerow(getattr(record, field) for field in CSV_FIELDS)

        _atomic_export(path, write)
    except Exception as error:
        raise CaptureFileError(f"Could not export CSV: {error}") from error