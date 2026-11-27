"""Run from the repository root: python -m unittest discover -s tests -v."""

import csv
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton
from scapy.all import Ether, IP, UDP, Raw, PcapWriter

from analyzer.packet_record import packet_to_record
from analyzer.pcap_files import CSV_FIELDS, CaptureFileError, export_csv, export_pcap, read_pcap
from gui import file_dialogs
from gui.main_window import MainWindow

ROOT = Path(__file__).resolve().parents[1]


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.packets = read_pcap(ROOT / "samples/mixed.pcap")
        self.records = [packet_to_record(packet) for packet in self.packets]

    def test_samples_and_missing_fields(self):
        self.assertEqual([record.protocol for record in self.records],
                         ["TCP", "TCP", "UDP", "ICMP", "Other"])
        self.assertEqual(self.records[3].src_port, "-")
        self.assertEqual(self.records[4].src_ip, "-")
        for name, count in [("tcp", 2), ("udp", 1), ("icmp", 1), ("arp", 1)]:
            self.assertEqual(len(read_pcap(ROOT / f"samples/{name}.pcap")), count)

    def test_pcap_roundtrip_preserves_bytes_and_times(self):
        # Include a nanosecond timestamp to exercise more than sample precision.
        from decimal import Decimal
        self.packets[0].time = Decimal("1800000000.123456789")
        destination = self.folder / "export.pcap"
        export_pcap(destination, self.records)
        restored = read_pcap(destination)
        self.assertEqual(len(restored), len(self.packets))
        for before, after in zip(self.packets, restored):
            self.assertEqual(bytes(before), bytes(after))
            self.assertEqual(before.time, after.time)

    def test_csv_fields_and_escaping(self):
        self.records[0].info = 'comma, quote " and\nnew line'
        destination = self.folder / "export.csv"
        export_csv(destination, self.records)
        with destination.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream))
        self.assertEqual(rows[0], list(CSV_FIELDS))
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[1][-1], self.records[0].info)
        self.assertEqual(rows[4][2], "-")

    def test_empty_exports_are_valid(self):
        destination = self.folder / "empty.pcap"
        export_pcap(destination, [])
        self.assertEqual(read_pcap(destination), [])
        destination = self.folder / "empty.csv"
        export_csv(destination, [])
        with destination.open(newline="") as stream:
            self.assertEqual(list(csv.reader(stream)), [list(CSV_FIELDS)])

    def test_invalid_missing_and_truncated_files(self):
        valid = (ROOT / "samples/mixed.pcap").read_bytes()
        bad_inputs = [b"", b"not a capture", valid[:12], valid[:30], valid[:-1]]
        for index, data in enumerate(bad_inputs):
            path = self.folder / f"bad{index}.pcap"
            path.write_bytes(data)
            with self.subTest(index=index), self.assertRaises(CaptureFileError):
                read_pcap(path)
        with self.assertRaises(CaptureFileError):
            read_pcap(self.folder / "missing.pcap")

    def test_big_endian_pcap(self):
        path = self.folder / "big-endian.pcap"
        with PcapWriter(str(path), endianness=">", linktype=1) as writer:
            writer.write(self.packets)
        self.assertEqual(len(read_pcap(path)), 5)

    def test_invalid_packet_length(self):
        data = bytearray((ROOT / "samples/tcp.pcap").read_bytes())
        data[32:36] = struct.pack("<I", 999999)
        path = self.folder / "invalid-length.pcap"
        path.write_bytes(data)
        with self.assertRaises(CaptureFileError):
            read_pcap(path)

    def test_failed_writes_preserve_existing_file_and_clean_up(self):
        path = self.folder / "existing.csv"
        path.write_bytes(b"keep me")
        with patch("analyzer.pcap_files.csv.writer", side_effect=OSError("disk full")):
            with self.assertRaises(CaptureFileError):
                export_csv(path, self.records)
        self.assertEqual(path.read_bytes(), b"keep me")
        self.assertEqual(list(self.folder.iterdir()), [path])
        with patch("analyzer.pcap_files.PcapWriter", side_effect=OSError("disk full")):
            with self.assertRaises(CaptureFileError):
                export_pcap(path, self.records)
        self.assertEqual(path.read_bytes(), b"keep me")
        self.assertEqual(list(self.folder.iterdir()), [path])

    def test_invalid_destination_and_permission_error(self):
        for exporter in [export_pcap, export_csv]:
            with self.subTest(exporter=exporter.__name__):
                with self.assertRaises(CaptureFileError):
                    exporter(self.folder / "missing" / "out", self.records)
                with patch("analyzer.pcap_files.os.replace", side_effect=PermissionError("read only")):
                    with self.assertRaises(CaptureFileError):
                        exporter(self.folder / "out", self.records)
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_mixed_link_types_are_rejected(self):
        raw_ip_record = packet_to_record(IP(src="192.0.2.1", dst="198.51.100.2") / UDP())
        with self.assertRaises(CaptureFileError):
            export_pcap(self.folder / "mixed-links.pcap", [self.records[0], raw_ip_record])
        self.assertFalse((self.folder / "mixed-links.pcap").exists())


class DialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.window = MainWindow()
        self.addCleanup(self.window.close)
        self.packets = read_pcap(ROOT / "samples/mixed.pcap")
        for packet in self.packets:
            self.window.packet_table.add_raw_packet(packet)
        self.messages = {}
        for name in ["critical", "information", "question"]:
            mock = self.enterContext(patch.object(file_dialogs.QMessageBox, name))
            self.messages[name] = mock

    def open_file(self, path):
        with patch.object(file_dialogs.QFileDialog, "getOpenFileName", return_value=(str(path), "")):
            file_dialogs.open_capture(self.window)

    def export_file(self, scope, file_format, path):
        with patch.object(file_dialogs.QInputDialog, "getItem",
                          side_effect=[(scope, True), (file_format, True)]):
            with patch.object(file_dialogs.QFileDialog, "getSaveFileName",
                              return_value=(str(path), "")):
                file_dialogs.export_capture(self.window)

    def test_open_replaces_table(self):
        self.open_file(ROOT / "samples/tcp.pcap")
        self.assertEqual(self.window.packet_table.rowCount(), 2)
        self.assertIn("2 of 2", self.window.statusBar().currentMessage())

    def test_failed_open_keeps_table(self):
        path = self.folder / "bad.pcap"
        path.write_bytes(b"bad")
        self.open_file(path)
        self.assertEqual(self.window.packet_table.rowCount(), 5)
        self.messages["critical"].assert_called_once()

    def test_cancel_open_keeps_table(self):
        self.open_file("")
        self.assertEqual(self.window.packet_table.rowCount(), 5)
        self.messages["critical"].assert_not_called()

    def test_empty_open_clears_table(self):
        path = self.folder / "empty.pcap"
        export_pcap(path, [])
        self.open_file(path)
        self.assertEqual(self.window.packet_table.rowCount(), 0)
        self.messages["information"].assert_called_once()

    def test_all_and_visible_exports(self):
        table = self.window.packet_table
        # Simulate the filter contract while master still has a matcher stub.
        with patch("analyzer.packet_table.packet_matches",
                   side_effect=lambda record, criteria: record.protocol == "TCP"):
            table.apply_filter({"protocol": "TCP"})
        for scope, count in [("All packets", 5), ("Visible packets (current filter)", 2)]:
            for file_format, suffix in [("PCAP", ".pcap"), ("CSV", ".csv")]:
                with self.subTest(scope=scope, file_format=file_format):
                    path = self.folder / f"out-{count}{suffix}"
                    self.export_file(scope, file_format, path)
                    if file_format == "PCAP":
                        self.assertEqual(len(read_pcap(path)), count)
                    else:
                        with path.open(newline="") as stream:
                            self.assertEqual(len(list(csv.reader(stream))) - 1, count)
        self.messages["critical"].assert_not_called()

    def test_cancel_at_every_export_dialog(self):
        for replies in [[("", False)], [("All packets", True), ("", False)]]:
            with patch.object(file_dialogs.QInputDialog, "getItem", side_effect=replies):
                file_dialogs.export_capture(self.window)
        self.export_file("All packets", "CSV", "")
        self.assertEqual(list(self.folder.iterdir()), [])
        self.messages["information"].assert_not_called()

    def test_extension_and_overwrite_confirmation(self):
        path = self.folder / "out.csv"
        path.write_text("keep me")
        self.messages["question"].return_value = QMessageBox.StandardButton.No
        self.export_file("All packets", "CSV", self.folder / "out")
        self.assertEqual(path.read_text(), "keep me")
        self.messages["question"].assert_called_once()
        self.messages["question"].return_value = QMessageBox.StandardButton.Yes
        self.export_file("All packets", "CSV", self.folder / "out")
        self.assertTrue(path.read_text().startswith("timestamp,"))

    def test_empty_selection(self):
        self.window.packet_table.clear_table()
        with patch.object(file_dialogs.QInputDialog, "getItem", return_value=("All packets", True)):
            with patch.object(file_dialogs.QFileDialog, "getSaveFileName") as save:
                file_dialogs.export_capture(self.window)
        save.assert_not_called()
        self.messages["information"].assert_called_once()

    def test_export_error_is_displayed(self):
        self.export_file("All packets", "PCAP", self.folder / "missing" / "out.pcap")
        self.messages["critical"].assert_called_once()

    def test_buttons_call_file_actions(self):
        for text, action in [("Open file...", "open_capture"), ("Export...", "export_capture")]:
            button = next(button for button in self.window.findChildren(QPushButton)
                          if button.text() == text)
            with patch("gui.main_window." + action) as handler:
                button.click()
            handler.assert_called_once_with(self.window)


if __name__ == "__main__":
    unittest.main()
