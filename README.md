# PacketSnifferApp
### Last Updated : Kat - Nov 20/2026

### Context:
We are building a wireshark style analyzer.
Should capture live packets / or open a pcap. 
Will show in a table, show details, filter, search, and export.

### Notes:
- wifi only (not enough time to build other live captures :,) 
- filtering shouldnt delete packets just hide them
- anything not IP/TCP/UDP/ICMP just call them "Other" protocols for now.
- if a packet doesn't have a value (like ports on ICMP), the field is "-"
- Please when working on this follow : open a new branch, make changes in your file, MERGE main into YOUR branch, resolve any conflicts, then open a PR and have someone else approve it or msg kat to look.

### For some context for the other files:
In packet record, check the fields please -
timestamp, src_ip, dest_ip, src_port, dest_port, protocol, length, info, raw_scapy_packet. May be useful for your section!

### Breakdown How we will do this:
Everyone take over one feature, (kat will make base template, build your gui part to fill in the template)

### PacketTable - kat
table model that holds packets
- will have add packet --> give it raw scapy packet to add a row (i think live capture and pcap will need this @yas @kulsum)
- record of all packets we have
- visible records -- packets that show with whatever given filter (@kavish) -- also something to set the filter
- a way to view specific records at a specific row
- some way to clear the table.

### live capture - kulsum
- i think you should only do wifi only given the time constraint
- run in background
- find wifi interface on whatever laptop we are using
- start / stop buttons for capture
- get every packet sent out as a raw scapy packet (Kat will connect it to the add packet @kat)
- make sure to handle errors if something goes wrong, so it doesnt just crash

### file in/out - yas
- open pcap files and save stuff out to them
- also please make some sample pcap files in /samples as soon as possible because we really need them to test with
- read a pcap file and give a list of scapy packets 
- if error then handle gracefully or give some readable error 
- export pcap (all packets or filterd ones)
- export csv : timestamp, src_ip, src_port, dest_ip, dest_port, protocol, length, info
- open dialog and export dialog

### detail pane - lara (also powerpoint)
show what is inside a selected packet
- turn a packet into its layers / show it --> Ethernet,IP,TCP/UDP/ICMP --> use raw_scapy_packet
- the pane itself should show the detials when a packet is selected, otherwise just show empty (recall wireshark)
- anything that isn't IP/TCP/UDP/ICMP should still show something

### filter/search - kavish
hide/show packets based on what user searches
- only hide dont delete
- check for packet against filter
- filter bar with protocol dropdown and text boxes (also a way to clear)
- send changes to kats table
- dont match packets with "-" for a field


### EXTRA:
### setup:
- python -m venv venv, then activate it
- pip install -r requirements.txt
- run with: python main.py
- live capture on Windows needs Npcap installed + run your terminal/IDE as administrator (Mac/Linux: sudo)

### what were agreeing on for now (so we can all start):
- packets get passed around as raw scapy packets
- kat's table has add_raw_packet(raw_scapy_packet) -- live capture and file reading both call this 
- kulsum: capture sends out each raw packet (please post name in chat so we know how to use it)
- yas: reading a pcap gives back a list of raw scapy packets. to export use get_all_packet_records() or get_visible_packet_records()
- kavish: filter is a dictionary like {"protocol": "TCP", etc}. kats table will have apply_filter(active_filter) that takes it
- lara: gets a packet record in and shows it. kats table will have get_record_at_row(table_row) to get it

Everything else (internal names, extra functions) is up to you just post in our chat please so we can use them!!

### PacketRecord (kat)
fields: timestamp, src_ip, dest_ip, src_port, dest_port, protocol, length, info, raw_scapy_packet
- missing values are "-"
- packet_to_record(packet) makes a PacketRecord from a raw scapy packet