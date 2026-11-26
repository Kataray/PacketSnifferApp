# Kavish Palan -- 11/24/2026

# checks if one packet record should be shown for the current filter
# active_filter is a dictionary like:
#   {"protocol": "TCP", "src_ip": "192.168", "src_port": "443", "dest_ip": "", "dest_port": ""}
# - missing, empty, or "All" entries are ignored (they let everything through)
# - a packet only has to match the boxes that are filled in
# - a packet with "-" in a field the user filled in never matches
# - this only decides what is shown, packets are never deleted
def packet_matches(record, active_filter):
    if not active_filter:
        return True

    # protocol dropdown (TCP / UDP / ICMP / Other, "All" = anything)
    wanted_protocol = active_filter.get("protocol", "All")
    if wanted_protocol not in ("", "All") and record.protocol != wanted_protocol:
        return False

    # ips: starts with what was typed, so "192.168" finds 192.168.1.5
    if not text_matches(active_filter.get("src_ip", ""), record.src_ip, exact=False):
        return False
    if not text_matches(active_filter.get("dest_ip", ""), record.dest_ip, exact=False):
        return False

    # ports: must be exactly what was typed
    if not text_matches(active_filter.get("src_port", ""), record.src_port, exact=True):
        return False
    if not text_matches(active_filter.get("dest_port", ""), record.dest_port, exact=True):
        return False

    return True


# compares what the user typed to one field of a packet
# exact=True -> whole value has to match, exact=False -> value has to start with it
def text_matches(typed_text, field_value, exact):
    typed_text = str(typed_text).strip().lower()

    # box left empty, so no filter on this field
    if typed_text == "":
        return True

    # packet has no value here ("-"), so it can't match what was typed
    if field_value == "-":
        return False

    field_value = str(field_value).lower()
    if exact:
        return field_value == typed_text
    return field_value.startswith(typed_text)
