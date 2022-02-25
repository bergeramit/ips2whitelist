#!/usr/bin/python3
from scapy.all import *
import sys, struct, re
from dnslib import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.INFO)
import warnings
warnings.simplefilter("ignore", Warning)

class InvalidCompressionOffset(Exception):
    pass

class InvalidLabelLengthOrMissingNullTerminator(Exception):
    pass

class InvalidLabelLengthTooShort(Exception):
    pass

class NoneAsciiLabelContent(Exception):
    pass

# Check name(check non compressed - label size, charachters)
def decode_name(s, pointer=0):
    max_length = len(s)
    name = b""
    cur_label_length = orb(s[pointer])
    Compressed = False
    while cur_label_length != 0:
        pointer += 1

        # Compressed label
        if cur_label_length == 0xc0:
            if s[pointer] > max_length:
                raise InvalidCompressionOffset("Invalid compression offset, bigger then packet size")
            label_content, pointer = decode_name(s,s[pointer])
            Compressed = True
        else:
            if cur_label_length > max_length:
                raise InvalidLabelLengthOrMissingNullTerminator("Invalid label length or missing Null terminator, bigger then packet size")
            if cur_label_length >= 65:
                raise InvalidLabelLengthTooShort("Invalid label length, label bounded by 64 bytes")
            label_content = s[pointer:pointer + cur_label_length]

        if not Compressed:
            pointer += cur_label_length
            name += label_content + b"."
            if not re.match(r'^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$', label_content.decode('utf-8'), re.IGNORECASE):
                raise NoneAsciiLabelContent("label content contains illegal non-ascii chars")
        else:
            Compressed = False
            name += label_content
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
        
    def parse_pkt(self, pkt):
        # Skip header
        pointer = 12

        for i in self.qcount:
            name, pointer = decode_name(pkt, pointer)
            self.names.append(name)
            self.actual_qcount += 1

            # Skip null, Type and class
            pointer += 5

        for i in self.ancount:
            name, pointer = decode_name(pkt, pointer)
            self.names.append(name)

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
        if (UDP in packet):
            if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                yield bytes(packet[UDP].payload)

# Every rule checks only specific paramater and assumes else is correct
def validate_QDCOUNT_is_the_amount_of_Question_section(pcap_path):
    for pkt in pkt_reader(pcap_path):
        d = DNSPacket(pkt)
        print("Parsed names: ", d.names)
        if d.qcount != d.actual_qcount:
            print("Wrong qdcount")
            return False
    return True

def validate_ANCOUNT_is_the_amount_of_Resource_record_answer(pcap_path):
    for pkt in pkt_reader(pcap_path):
        d = DNSPacket(pkt)
        print("Parsed names: ", d.names)
        if d.ancount != d.actual_ancount:
            print("Wrong ancount")
            return False
    return True

def validate_NAME_only_contains_ASCII(pcap_path):
    for pkt in pkt_reader(pcap_path):
        try:
            DNSPacket(pkt)
        except NoneAsciiLabelContent:
            return False
        except Exception:
            return True
        # print("Parsed names: ", d.names)
    return True

def validate_NAME_labels_in_the_CORRECT_SIZE(pcap_path):
    for pkt in pkt_reader(pcap_path):
        try:
            DNSPacket(pkt)
        except InvalidLabelLengthOrMissingNullTerminator:
            return False
        except InvalidLabelLengthTooShort:
            return False
        except Exception:
            return True
        # print("Parsed names: ", d.names)
    return True

def validate_NAME_compression_offset_is_LEGAL(pcap_path):
    for pkt in pkt_reader(pcap_path):
        try:
            DNSPacket(pkt)
        except InvalidCompressionOffset:
            return False
        except Exception:
            return True
        # print("Parsed names: ", d.names)
    return True


def validate_QNAME_not_contain_0(pcap_path):
    for pkt in pkt_reader(pcap_path):
        try:
            DNSPacket(pkt)
        except InvalidLabelLengthOrMissingNullTerminator:
            return False
        except InvalidLabelLengthTooShort:
            return False
        except Exception:
            return True
        # print("Parsed names: ", d.names)
    return True


# print(check_name_labels_length(r"whitelist_compressed_answer.pcap"))
# print(check_name_labels_length(r"ap2_wrong_label_size.pcap"))
# print(check_names_null_terminator(r"ap3_missing_null_terminator.pcap"))
# print(check_qdcount(r"ap4_wrong_counts.pcap"))
# print(check_ancount(r"ap4_wrong_counts.pcap"))
# print(check_names_compression_offsets(r"ap5_wrong_compression_offset.pcap"))
# print(check_names_non_ascii(r"CVE-2020-11901.pcap"))