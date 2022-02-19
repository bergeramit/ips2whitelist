from pytest import mark

@mark.parametrize('pcap_path', [
    (os.path.join('tests','test_tcp','todo.pcap')),
])
def test_whitelist_rule_on_pcap(whitelist_rule, pcap_path, run_pcap_with_rule):
    assert len(run_pcap_with_rule(pcap_path, whitelist_rule)) > 0
