# Kavish Palan -- 11/24/2026

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget

# the filter bar shown above the packet table
# has a protocol dropdown, four text boxes (src/dest ip + port) and a clear button
# whenever something changes it sends out the filter dictionary through filter_changed
class FilterBar(QWidget):
    filter_changed = pyqtSignal(dict)

    def __init__(self):
        super().__init__()

        self.protocol_dropdown = QComboBox()
        self.protocol_dropdown.addItems(["All", "TCP", "UDP", "ICMP", "Other"])
        self.src_ip_box = self.make_text_box(140, "e.g. 192.168")
        self.src_port_box = self.make_text_box(70, "e.g. 443")
        self.dest_ip_box = self.make_text_box(140, "e.g. 10.0")
        self.dest_port_box = self.make_text_box(70, "e.g. 80")
        self.clear_button = QPushButton("Clear filters")

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel("Protocol:"))
        layout.addWidget(self.protocol_dropdown)
        layout.addWidget(QLabel("Source IP:"))
        layout.addWidget(self.src_ip_box, 3)
        layout.addWidget(QLabel("Source Port:"))
        layout.addWidget(self.src_port_box, 1)
        layout.addWidget(QLabel("Dest IP:"))
        layout.addWidget(self.dest_ip_box, 3)
        layout.addWidget(QLabel("Dest Port:"))
        layout.addWidget(self.dest_port_box, 1)
        layout.addWidget(self.clear_button)
        self.setLayout(layout)

        # waits a moment after typing stops so the table isnt rebuilt on every key press
        self.typing_timer = QTimer()
        self.typing_timer.setSingleShot(True)
        self.typing_timer.setInterval(250)
        self.typing_timer.timeout.connect(self.send_filter)

        self.protocol_dropdown.currentTextChanged.connect(self.send_filter)
        for text_box in self.get_text_boxes():
            text_box.textChanged.connect(self.typing_timer.start)
            text_box.returnPressed.connect(self.send_filter)
        self.clear_button.clicked.connect(self.clear_filters)

    # makes a text box
    def make_text_box(self, minimum_width, hint):
        text_box = QLineEdit()
        text_box.setMinimumWidth(minimum_width)
        text_box.setPlaceholderText(hint)
        return text_box

    def get_text_boxes(self):
        return [self.src_ip_box, self.src_port_box, self.dest_ip_box, self.dest_port_box]

    # builds the filter dictionary from whatever is in the bar right now
    def get_filter(self):
        return {
            "protocol": self.protocol_dropdown.currentText(),
            "src_ip": self.src_ip_box.text().strip(),
            "src_port": self.src_port_box.text().strip(),
            "dest_ip": self.dest_ip_box.text().strip(),
            "dest_port": self.dest_port_box.text().strip(),
        }

    # sends the current filter to whoever is listening (the table)
    def send_filter(self):
        self.typing_timer.stop()
        self.filter_changed.emit(self.get_filter())

    # puts everything back to default and shows all packets again
    def clear_filters(self):
        # block signals so the table only gets updated once
        self.protocol_dropdown.blockSignals(True)
        self.protocol_dropdown.setCurrentIndex(0)
        self.protocol_dropdown.blockSignals(False)
        for text_box in self.get_text_boxes():
            text_box.blockSignals(True)
            text_box.clear()
            text_box.blockSignals(False)
        self.send_filter()
