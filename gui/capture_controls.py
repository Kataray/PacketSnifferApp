# TODO: kulsum - start/stop buttons

from PyQt6.QtWidgets import *
from analyzer.live_capture import start_live_capture, stop_live_capture

def start_capture_clicked(window, start_button, stop_button):
    # if start already clicked, do nothing
    try:
        start_live_capture()
    except Exception as e:
        QMessageBox.critical(window, "Error", f"Failed to start live capture: {str(e)}")
        return

    # begin updating packet table view (todo)

    start_button.setEnabled(False)
    stop_button.setEnabled(True)

def stop_capture_clicked(window, start_button, stop_button):
    try:
        stop_live_capture()
    except Exception as e:
        QMessageBox.critical(window, "Error", f"Failed to stop live capture: {str(e)}")
        return

    # stop updating packet table view (todo)

    start_button.setEnabled(True)
    stop_button.setEnabled(False)