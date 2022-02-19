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
        'tcp': 'examples\\tcp_whitelist.txt',
        'dns': 'examples\\dns_whitelist.txt'
    }
    with open(WHITELIST_PER_ENV[request.config.getoption('--env')], "rb") as f:
        rules = [line.strip() for line in f.readlines()]
    return rules