# proxyspy

[![Build and Test](https://github.com/anaconda/proxyspy/actions/workflows/main.yaml/badge.svg)](https://github.com/anaconda/proxyspy/actions/workflows/main.yaml)
[![Latest Release](https://img.shields.io/github/v/release/anaconda/proxyspy?include_prereleases)](https://github.com/anaconda/proxyspy/releases/latest)
[![PyPI version](https://img.shields.io/pypi/v/proxyspy.svg)](https://pypi.org/project/proxyspy/)
[![Conda Version](https://img.shields.io/conda/v/conda-forge/proxyspy)](https://anaconda.org/conda-forge/proxyspy)

proxyspy shows you the HTTPS requests your program sends and the responses it
gets back. To see both sides of one request, install it with
`conda install conda-forge::proxyspy` or `python -m pip install proxyspy`, then run:

```sh
proxyspy -l headers.log -- curl -I https://example.org/
```

curl prints the response headers. In `headers.log`, look for `[C->S] HEAD /`
to see what curl sent and `[S->C]` for the server's reply. proxyspy sets up the
proxy and certificate trust for this command only. The log contains decrypted
traffic, so use test credentials and check logs before sharing them.

## Choose a guide

- [Inspect headers from a conda test](https://github.com/anaconda/proxyspy/blob/main/docs/forward.md#inspect-the-headers-conda-sends): let the forward proxy start the client and stop when it exits.
- [Try a local Wrangler Worker](https://github.com/anaconda/proxyspy/blob/main/docs/forward.md#send-a-channel-request-to-a-local-worker): leave the forward proxy running and try several clients without changing their channel URLs.
- [Test behind a TLS-terminating firewall](https://github.com/anaconda/proxyspy/blob/main/docs/reverse.md): use the reverse proxy when the client must make a direct HTTPS connection with no proxy configured.
- [Change what happens to a request](https://github.com/anaconda/proxyspy/blob/main/docs/options.md): choose an upstream, add a request header, return a canned response, or delay a connection.

The guides use proxyspy 0.3 or later and POSIX shell syntax. Run
`proxyspy --help` for the options available in your installation.

## Development

proxyspy is a [single Python file](https://github.com/anaconda/proxyspy/blob/main/proxyspy.py).
You can vendor it and run `python proxyspy.py` with Python 3.10+ and
`cryptography`, its only third-party runtime dependency. Please keep it that
way when contributing, and include tests for new behavior. From a checkout:

```sh
conda install --file requirements.txt
python -m pytest -v
```

The original implementation and test suite were developed with Claude 3.5 and
3.7 Sonnet.
