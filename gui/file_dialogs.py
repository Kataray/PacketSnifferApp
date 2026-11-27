from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

from analyzer.packet_record import packet_to_record
from analyzer.pcap_files import CaptureFileError, export_csv, export_pcap, read_pcap


def open_capture(window):
    """Read the entire capture successfully before replacing current packets."""
    path, _ = QFileDialog.getOpenFileName(
        window, "Open PCAP", "", "PCAP files (*.pcap);;All files (*)",
    )
    if not path:
        return
    try:
        packets = read_pcap(path)
        # Ensure every packet can be displayed before clearing old data.
        for packet in packets:
            packet_to_record(packet)
    except Exception as error:
        QMessageBox.critical(window, "Open failed", str(error))
        return

    window.packet_table.clear_table()
    for packet in packets:
        window.packet_table.add_raw_packet(packet)
    if not packets:
        QMessageBox.information(window, "Empty capture", "This capture contains no packets.")


def export_capture(window):
    """Ask for scope, format and filename, then export the chosen records."""
    scope, accepted = QInputDialog.getItem(
        window, "Export packets", "Which packets?",
        ["All packets", "Visible packets (current filter)"], 0, False,
    )
    if not accepted:
        return
    table = window.packet_table
    records = list(
        table.get_all_packet_records() if scope == "All packets"
        else table.get_visible_packet_records()
    )
    if not records:
        QMessageBox.information(window, "Nothing to export", "There are no packets in this selection.")
        return

    file_format, accepted = QInputDialog.getItem(
        window, "Export format", "File format:", ["PCAP", "CSV"], 0, False,
    )
    if not accepted:
        return
    extension = ".pcap" if file_format == "PCAP" else ".csv"
    path, _ = QFileDialog.getSaveFileName(
        window, "Export packets", "packets" + extension,
        f"{file_format} files (*{extension})",
        options=QFileDialog.Option.DontConfirmOverwrite,
    )
    if not path:
        return
    if Path(path).suffix.lower() != extension:
        path += extension
    # Confirm the final filename after adding the extension.
    if Path(path).exists():
        answer = QMessageBox.question(
            window, "Replace file?", f"Replace {Path(path).name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
    try:
        exporter = export_pcap if file_format == "PCAP" else export_csv
        exporter(path, records)
    except CaptureFileError as error:
        QMessageBox.critical(window, "Export failed", str(error))
        return
    QMessageBox.information(
        window, "Export complete", f"Exported {len(records)} packets to:\n{path}",
    )