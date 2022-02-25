#!/usr/bin/python3
from scapy.all import *
import sys, struct
from dnslib import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.INFO)

# Check name(check non compressed - label size, charachters)
def decode_name(s,pointer=0):
    max_length = len(s)
    name = b""
    cur_label_length = orb(s[pointer])

    while cur_label_length != 0:
        pointer += 1

        # Compressed label
        if cur_label_length & 0xc0:
            label_content, pointer = decode_name(s,s[pointer])
            Compressed = True
        else:
            if (cur_label_length >= len(s) - cur_label_length) or (cur_label_length >= 65):
                raise Exception("Invalid label length")
            label_content = s[pointer:pointer + cur_label_length]

        valid_name_regex = re.compile(r'^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$', re.IGNORECASE)
        if not valid_name_regex.match(label_content.decode('utf-8')):
            raise Exception("label content contains illegal non-ascii chars")
        pointer += cur_label_length
        name += label_content + b"."
        cur_label_length = orb(s[pointer])
    return name, pointer

class DNSPacket():
    def __init__(self, pkt):
        self.pkt = pkt
        self.qcount = struct.unpack("!H", pkt[4:6])
        self.actual_qcount = 0
        self.ancount = struct.unpack("!H", pkt[6:8])
        self.actual_ancount = 0
        self.authority_rr = struct.unpack("!H", pkt[8:10])
        self.additional_rr = struct.unpack("!H", pkt[10:12])
        self.names = []
        self.parse_pkt(pkt)
        self.pointer = 0
        
    def parse_pkt(self, pkt):
        # Skip header
        pointer = 12

        for i in self.qcount:
            try:
                name, pointer = decode_name(pkt, pointer)
                self.names.append(name)
            except:
                # Ignore counters related exceptions
                pass
            self.actual_qcount += 1

            # Skip null, Type and class
            pointer += 5

        for i in self.ancount:
            try:
                name, pointer = decode_name(pkt, pointer)
                self.names.append(name)
            except:
                # Ignore counters related exceptions
                pass
            # Skip null, Type and class, ttl, data length, address
            pointer += 14
            self.actual_ancount += 1
        # Can't parse authority_rr, additional_rr because their size isn't fixed and optional so we'll skip those
        self.pointer = pointer + 8


# A simple generator function
def pkt_reader(pcap_path):
    pcap = rdpcap(pcap_path)
    print("Loaded PCAP: ",pcap_path)
    for packet in pcap:
        if (DNS in packet):
            yield bytes(packet[UDP].payload)

# Every rule checks only specific paramater and assumes else is correct
def check_qcount(pcap_path):
    for pkt in pkt_reader(pcap_path):
        d = DNSPacket(pkt)
        print("Parsed names: ", d.names)
        if d.qcount != d.actual_qcount:
            print("Wrong qcount")
            return False
            
    return True

def check_ancount(pcap_path):
    for pkt in pkt_reader(pcap_path):
        d = DNSPacket(pkt)
        print("Parsed names: ", d.names)
        if d.ancount != d.actual_ancount:
            print("Wrong ancount")
            return False
    return True

def check_names_non_ascii(pcap_path):
    valid_name_regex = re.compile(r'^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$', re.IGNORECASE)
    if not Label.valid_name_regex.match(value):
        raise ValueError(_("bad label: '%s'") % value)
    return CIStr.__new__(cls, value)

    return True

def check_name_labels_length(pcap_path):
    for pkt in pkt_reader(pcap_path):
        d = DNSPacket(pkt)
        # Skip header
        for i in d.qcount:
            try:
                name, pointer = decode_name(pkt, pointer)
                self.names.append(name)
            except:
                return False
        for i in d.ancount:
            try:
                name, pointer = decode_name(pkt, pointer)
                self.names.append(name)
            except:
                return False
    return True

def check_names_compression_offsets(pcap_path):
    return True

def check_names_null_terminator(pcap_path):
    return True


print(check_qcount(r"ap4_wrong_counts.pcap"))
print(check_ancount(r"ap4_wrong_counts.pcap"))
print(check_name_labels_length(r"ap2_wrong_label_size.pcap"))
#check_name_labels_length(r"whitelist_compressed_answer.pcap")