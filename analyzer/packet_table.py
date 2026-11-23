# Katarina Mantay -- 11/22/2026

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from analyzer.packet_record import packet_to_record
from analyzer.packet_filter import packet_matches

# will be the packet table shown in the GUI
class PacketTable(QAbstractTableModel):
    column_names = ["No.", "Time", "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "Length", "Info"]

    def __init__(self):
        super().__init__()
        self.all_packet_records = []
        self.visible_packet_records = []
        self.active_filter = {}
        self.first_packet_time = None

    # reutrns num of visible rows
    def rowCount(self, parent=QModelIndex()):
        return len(self.visible_packet_records)

    # returns num of columns
    def columnCount(self, parent=QModelIndex()):
        return len(self.column_names)

    # gives the table its column titles
    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.column_names[section]

    # gives the table the text for each cell
    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        record = self.visible_packet_records[index.row()]
        column = index.column()

        if column == 0:
            return index.row() + 1
        if column == 1:
            return f"{record.timestamp - self.first_packet_time:.6f}"
        if column == 2:
            return record.src_ip
        if column == 3:
            return record.src_port
        if column == 4:
            return record.dest_ip
        if column == 5:
            return record.dest_port
        if column == 6:
            return record.protocol
        if column == 7:
            return record.length
        if column == 8:
            return record.info

    # turns a raw scapy packet into a record and adds it to the table
    def add_raw_packet(self, raw_scapy_packet):
        record = packet_to_record(raw_scapy_packet)
        if self.first_packet_time is None:
            self.first_packet_time = record.timestamp
        self.all_packet_records.append(record)

        # only show it if it passes the filter
        if packet_matches(record, self.active_filter):
            new_row = len(self.visible_packet_records)
            self.beginInsertRows(QModelIndex(), new_row, new_row)
            self.visible_packet_records.append(record)
            self.endInsertRows()

    # returns all packet records
    def get_all_packet_records(self):
        return self.all_packet_records

    # returns packet records that pass filter
    def get_visible_packet_records(self):
        return self.visible_packet_records

    # returns packet record at a specific row
    def get_record_at_row(self, table_row):
        return self.visible_packet_records[table_row]

    # rebuilds the visible list using the new filter
    def apply_filter(self, active_filter):
        self.active_filter = active_filter
        self.beginResetModel()
        self.visible_packet_records = []
        for record in self.all_packet_records:
            if packet_matches(record, self.active_filter):
                self.visible_packet_records.append(record)
        self.endResetModel()

    # clear everything from the table
    def clear_table(self):
        self.beginResetModel()
        self.all_packet_records = []
        self.visible_packet_records = []
        self.first_packet_time = None
        self.endResetModel()