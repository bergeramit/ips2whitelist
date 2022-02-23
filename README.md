# ips2whitelist

Try our examples!
```
python ips2whitelist.py examples\description_rfc1035.txt examples\dns_whitelist.txt
# OR
python ips2whitelist.py examples\description_tcp.txt examples\tcp_whitelist.txt
```

# Tests

Run with:
```
pytest -sv --env=dns tests\test_dns
# Or for TCP
pytest -sv --env=tcp tests\test_tcp
```

On linux with pytest run:
```
pytest-3 -sv --env=dns tests\test_dns
# Or for TCP
pytest-3 -sv --env=tcp tests\test_tcp
```
