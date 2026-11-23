# Katarina Mantay -- 11/20/2026

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *
from analyzer.packet_table import PacketTable

from analyzer.live_capture import start_live_capture
from analyzer.live_capture import stop_live_capture

# TODO kat: uncomment 4 lines related to table once the real PacketTable is pushed (reminder for myself lol)
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PacketSnifferApp")
        self.resize(1200, 800)

        # creates the table, the UI view, uses the data, selects entire row, stretches table.
        self.packet_table = PacketTable()
        self.packet_table_view = QTableView()
        #self.packet_table_view.setModel(self.packet_table)
        self.packet_table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table_view.horizontalHeader().setStretchLastSection(True)

        # i created some temp stand ins but @yas @lara @kulsum @kavish replace when doing please
        self.capture_controls = self.make_capture_controls()  
        self.file_buttons = self.make_file_buttons()           
        self.filter_bar = self.make_filter_bar()               
        self.detail_pane = self.make_detail_pane()             

        # capture controls and file buttons
        top_row = QHBoxLayout()
        top_row.addWidget(self.capture_controls)
        top_row.addWidget(self.file_buttons)
        top_row.addStretch()

        # layout (controls/files -> filter -> packet table -> detail box)
        main_layout = QVBoxLayout()
        main_layout.addLayout(top_row)
        main_layout.addWidget(self.filter_bar)
        main_layout.addWidget(self.packet_table_view, 3)
        main_layout.addWidget(self.detail_pane, 1)

        # put layout in window
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # show detail pane on click
        #self.packet_table_view.selectionModel().currentRowChanged.connect(self.on_row_selected)

        # status bar (how many packets)
        #self.packet_table.rowsInserted.connect(self.update_status_bar)
        #self.packet_table.modelReset.connect(self.update_status_bar)
        self.update_status_bar()

    # NOTE : the parts down here need to be REPLACED/WORKED ON by whoever is assigned that part, these are placeholders cuz I wanted to test the UI

    # kulsum: Wi-Fi label start and stop buttons
    def make_capture_controls(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel("Interface:"))
        layout.addWidget(QLabel("Wi-Fi"))

        # start: call live capture method from live_capture.py
        start_button = QPushButton("Start capture")
        start_button.clicked.connect(self.start_capture_clicked)
        layout.addWidget(start_button)

        # stop: call method to stop live capture from live_capture.py
        stop_button = QPushButton("Stop")
        stop_button.clicked.connect(self.stop_capture_clicked)
        layout.addWidget(stop_button)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    # NEW method: when "start" clicked (kulsum)
    def start_capture_clicked(self):
        # if start already clicked, do nothing
        if self.packet_table_view is not None and self.packet_table_view.isVisible():
            QMessageBox.warning(self, "Warning", "Capture is already running.")
            return

        try:
            start_live_capture()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start live capture: {str(e)}")
            return

        # begin updating packet table view (todo)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    # NEW method: when "stop" clicked (kulsum)
    def stop_capture_clicked(self):
        try:
            stop_live_capture()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop live capture: {str(e)}")
            return

        # stop updating packet table view (todo)

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    # yas: open and export buttons
    def make_file_buttons(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QPushButton("Open file..."))
        layout.addWidget(QPushButton("Export..."))
        widget = QWidget()
        widget.setLayout(layout)
        return widget

    # kavish: protocol dropdown and four text boxes, clear button
    def make_filter_bar(self):
        protocol_dropdown = QComboBox()
        protocol_dropdown.addItems(["All", "TCP", "UDP", "ICMP", "Other"])

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel("Protocol:"))
        layout.addWidget(protocol_dropdown)
        layout.addWidget(QLabel("Source IP:"))
        layout.addWidget(self.make_text_box(140), 3)
        layout.addWidget(QLabel("Source Port:"))
        layout.addWidget(self.make_text_box(70), 1)
        layout.addWidget(QLabel("Dest IP:"))
        layout.addWidget(self.make_text_box(140), 3)
        layout.addWidget(QLabel("Dest Port:"))
        layout.addWidget(self.make_text_box(70), 1)
        layout.addWidget(QPushButton("Clear filters"))
        widget = QWidget()
        widget.setLayout(layout)
        return widget

    # makes a text box
    def make_text_box(self, minimum_width):
        text_box = QLineEdit()
        text_box.setMinimumWidth(minimum_width)
        return text_box

    # lara: the box that shows what's inside the selected packet
    def make_detail_pane(self):
        label = QLabel("detail pane (lara) - click a packet to see it here")
        label.setStyleSheet("border: 1px solid gray; padding: 8px;")
        label.setAlignment(Qt.AlignmentFlag.AlignTop)
        label.setWordWrap(True)
        return label    

    # this needs to be replaced @lara when you do the detail pane
    def on_row_selected(self, current_index, previous_index):
        row = current_index.row()
        if row < 0:
            return
        record = self.packet_table.get_record_at_row(row)
        self.detail_pane.setText(record.info)    

    # how many packets are visible out of total
    def update_status_bar(self):
        visible_count = len(self.packet_table.get_visible_packet_records())
        total_count = len(self.packet_table.get_all_packet_records())
        self.statusBar().showMessage(f"{visible_count} of {total_count} packets")