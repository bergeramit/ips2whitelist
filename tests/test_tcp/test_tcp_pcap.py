from pytest import mark

@mark.parametrize('pcap_path', [
    ('test_tcp.pcap'),
])
def test_whitelist_on_pcap(whitelist, pcap_path):
    print(whitelist)
    print(pcap_path)
    assert True
