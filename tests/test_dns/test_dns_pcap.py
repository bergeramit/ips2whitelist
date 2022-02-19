import os
from pytest import mark

@mark.parametrize('pcap_path', [
    (os.path.join('tests','test_dns','simple_query_non_zero_Z.pcap')),
])
def test_whitelist_on_pcap(whitelist, pcap_path, run_pcap_with_rule):
    print(whitelist)
    print(pcap_path)
    assert all([run_pcap_with_rule(pcap_path, rule) for rule in whitelist])

