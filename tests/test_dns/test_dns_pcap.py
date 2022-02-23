import os
from pytest import mark

@mark.parametrize('pcap_path', [
    "simple_query_non_zero_Z.pcap",
    "ap2_wrong_label_size.pcap",
    "ap5_wrong_compression_offset.pcap",
    "simple_query_non_zero_Z.pcap",
    "static_rr_class_ge_4.pcap",
    "ap3_missing_null_terminator.pcap",
    "CVE-2020-11901.pcap",
    "static_non_zero_Z.pcap",
    "static_rr_qclass_ge_4_le_255.pcap",
    "whitelist_compressed_answer.pcap",
    "ap4_wrong_counts.pcap",
    "static_rcode_ge_4.pcap",
    "static_rr_type_ge_16.pcap",
    "whitelist_simple_query.pcap",
])
def test_whitelist_rule_on_pcap(whitelist_rule, pcap_path, run_pcap_with_rule):
    assert len(run_pcap_with_rule(os.path.join('tests','test_dns', pcap_path), whitelist_rule)) > 0

