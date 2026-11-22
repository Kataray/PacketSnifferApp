# TODO: kulsum - live capture thread
import queue
import threading

from scapy.all import AsyncSniffer

from analyzer.packet_table import PacketTable

PACKET_QUEUE = queue.Queue(maxsize=17000)

_sniffer = None
_thread = None
_stop_event = threading.Event()
_packet_table = PacketTable()

_dropped_packets = 0
_dropped_lock = threading.Lock()

# create a queue of all raw packets then send them to packet table to be added
# multithreading with a queue to prevent packet loss

def packet_callback(raw_packet):
    global _dropped_packets
    try:
        PACKET_QUEUE.put_nowait(raw_packet)
    except queue.Full:
        with _dropped_lock:
            _dropped_packets += 1

def add_to_packet_table():
    while not _stop_event.is_set():
        try:
            raw_packet = PACKET_QUEUE.get(timeout=0.55)
        except queue.Empty:
            continue
        try:
            _packet_table.add_raw_packet(raw_packet)
        except Exception as e:
            print(f"live capture error: adding packet to table: {e}")
        finally:
            PACKET_QUEUE.task_done()


def start_live_capture():
    global _sniffer, _thread, _stop_event

    # todo: dialog box in gui for error
    if _sniffer is not None:
        print("capture is already running.")
        return

    _stop_event.clear()

    _thread = threading.Thread(
        target=add_to_packet_table, name="LiveCaptureThread", daemon=True
    )
    _thread.start()

    _sniffer = AsyncSniffer(iface="wifi", prn=packet_callback)
    _sniffer.start()

    return _sniffer


def stop_live_capture(timeout=5):
    global _sniffer, _thread, _stop_event

    # todo: dialog box in gui
    if _sniffer is None:
        print("capture is not running.")
        return

    _sniffer.stop()
    _sniffer = None

    _stop_event.set()

    if _thread is not None:
        _thread.join(timeout=timeout)
        _thread = None

    # clear packet queue once capture stopped
    while not PACKET_QUEUE.empty():
        try:
            PACKET_QUEUE.get_nowait()
            PACKET_QUEUE.task_done()
        except queue.Empty:
            break

def get_dropped_packet_count():
    with _dropped_lock:
        return _dropped_packets