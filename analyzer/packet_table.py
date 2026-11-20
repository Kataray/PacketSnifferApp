# Katarina Mantay -- 11/20/2026
# this is temporary rn until I finish the code for this -- but names are helpful for you guys to use the functions/vars

# will be the packet table shown in the GUI
class PacketTable:
    def __init__(self):
        self.all_packet_records = []
        self.visible_packet_records = []

    # todo 
    def add_raw_packet(self, raw_scapy_packet):
        pass

    # returns all packet records
    def get_all_packet_records(self):
        return self.all_packet_records

    # returns packet records that pass filter
    def get_visible_packet_records(self):
        return self.visible_packet_records

    # returns packet record at a specific row
    def get_record_at_row(self, table_row):
        return self.visible_packet_records[table_row]

    # todo
    def apply_filter(self, active_filter):
        pass

    # clear everything from the table
    def clear_table(self):
        self.all_packet_records = []
        self.visible_packet_records = []

