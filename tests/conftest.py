import time
import os
from subprocess import Popen, PIPE

from pytest import fixture

def pytest_addoption(parser):
    parser.addoption(
        '--env',
        action="store",
        help="Whitelist file to run tests on"
    )

@fixture(scope='session')
def whitelist(request):
    WHITELIST_PER_ENV = {
        'tcp': os.path.join('examples','tcp_whitelist.txt'),
        'dns': os.path.join('examples','dns_whitelist.txt'),
    }
    with open(WHITELIST_PER_ENV[request.config.getoption('--env')], "rb") as f:
        rules = [line.strip() for line in f.readlines()]
    return rules


@fixture(scope='session')
def run_pcap_with_rule():
    def _run_pcap_with_rule(pcap_path, whitelist_rule):
        pipe = Popen(['tcpdump', '-pnnvvr', f'{pcap_path}', f'{whitelist_rule}'], stdout=PIPE)
        time.sleep(1)
        return pipe.communicate()[0]
    return _run_pcap_with_rule
