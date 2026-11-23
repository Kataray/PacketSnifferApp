# TODO: kulsum - live capture thread
import queue
import threading

import platform, os

from scapy.all import AsyncSniffer, conf

from analyzer.packet_table import PacketTable

PACKET_QUEUE = queue.Queue(maxsize=17000)

_sniffer = None
_thread = None
_stop_event = threading.Event()

_dropped_packets = 0
_dropped_lock = threading.Lock()

def packet_callback(raw_packet):
    global _dropped_packets
    try:
        PACKET_QUEUE.put_nowait(raw_packet)
    except queue.Full:
        with _dropped_lock:
            _dropped_packets += 1

# def add_to_packet_table():
#     while not _stop_event.is_set():
#         try:
#             raw_packet = PACKET_QUEUE.get(timeout=0.55)
#         except queue.Empty:
#             continue
#         try:
#             _packet_table.add_raw_packet(raw_packet)
#         except Exception as e:
#             print(f"live capture error: adding packet to table: {e}")
#         finally:
#             PACKET_QUEUE.task_done()

def get_wifi_interface():
    sys = platform.system().lower()
    wifi_iface = None

    if sys == "windows":
        for iface in conf.ifaces.values():
            info = (iface.description or "").lower()
            name = (iface.name or "").lower()
            if "wi-fi" in info or "wi-fi" in name or "wireless" in info or "wlan" in name:
                wifi_iface = iface.name
                break

    if sys == "linux":
        for iface in conf.ifaces.values():
            name = (iface.name or "").lower()
            if os.path.exists(f"/sys/class/net/{name}/wireless"):
                wifi_iface = iface.name
                break

    if sys == "darwin":
        for iface in conf.ifaces.values():
            name = (iface.name or "").lower()
            if "en" in name:
                wifi_iface = iface.name
                break

    return wifi_iface



def start_live_capture():
    global _sniffer, _stop_event

    if _sniffer is not None:
        print("capture is already running.")
        return _sniffer

    _stop_event.clear()

    test = get_wifi_interface()
    print(f"Starting live capture on interface: {test}")
    _sniffer = AsyncSniffer(iface=test, prn=packet_callback, store=False)
    _sniffer.start()

    return 


def stop_live_capture():
    global _sniffer

    _stop_event.set()

    if _sniffer is not None:
        if _sniffer.running:
            _sniffer.stop()
        _sniffer = None
        print("capture is not running.")
    else:
        print("capture is not running.") #todo: dialog box

    # clear packet queue once capture stopped
    while not PACKET_QUEUE.empty():
        try:
            PACKET_QUEUE.get_nowait()
            PACKET_QUEUE.task_done()
        except queue.Empty:
            break

    return

def get_dropped_packet_count():
    with _dropped_lock:
        return _dropped_packets