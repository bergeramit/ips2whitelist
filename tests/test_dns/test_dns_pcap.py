import os
from pytest import mark

@mark.parametrize('pcap_path', [
    (os.path.join('tests','test_dns','simple_query_non_zero_Z.pcap')),
])
def test_whitelist_rule_on_pcap(whitelist_rule, pcap_path, run_pcap_with_rule):
    assert len(run_pcap_with_rule(pcap_path, whitelist_rule)) > 0

