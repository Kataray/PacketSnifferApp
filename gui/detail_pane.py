from PyQt6.QtWidgets import QAbstractItemView, QTableWidget, QTableWidgetItem

from analyzer.packet_details import packet_layers


class DetailPane(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setAccessibleName("Selected packet details")
        self.verticalHeader().hide()
        self.horizontalHeader().setStretchLastSection(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    def clear(self):
        self.setRowCount(0)
        self.setColumnCount(0)

    def show_record(self, record):
        self.clear()
        if record is None:
            return

        headers = []
        values = []
        for layer, fields in packet_layers(record):
            for label, value in fields:
                headers.append(f"{layer} · {label}")
                values.append(value)

        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.setRowCount(1)

        for column, value in enumerate(values):
            self.setItem(0, column, QTableWidgetItem(str(value)))

        self.resizeColumnsToContents()
        self.horizontalScrollBar().setValue(0)