# proxyspy

[![Build and Test](https://github.com/anaconda/proxyspy/actions/workflows/main.yaml/badge.svg)](https://github.com/anaconda/proxyspy/actions/workflows/main.yaml)
[![Latest Release](https://img.shields.io/github/v/release/anaconda/proxyspy?include_prereleases)](https://github.com/anaconda/proxyspy/releases/latest)
[![PyPI version](https://img.shields.io/pypi/v/proxyspy.svg)](https://pypi.org/project/proxyspy/)
[![Conda Version](https://img.shields.io/conda/v/conda-forge/proxyspy)](https://anaconda.org/conda-forge/proxyspy)

proxyspy shows you the HTTPS requests your program sends and the responses it
gets back. To see both sides of one request, install it with
`python -m pip install proxyspy` or `conda install conda-forge::proxyspy`, then run:

```sh
proxyspy -l headers.log -- curl -I https://example.org/
```

curl prints the response headers. In `headers.log`, look for `[C->S] HEAD /`
to see what curl sent and `[S->C]` for the server's reply. proxyspy sets up the
proxy and certificate trust for this command only. The log contains decrypted
traffic, so use test credentials and check logs before sharing them.

## Choose a guide

- [See what a client sends](https://github.com/anaconda/proxyspy/blob/main/docs/forward.md#inspect-an-outgoing-request): run a command or test suite under the forward proxy and read the request alongside the server's response.
- [Compare two clients](https://github.com/anaconda/proxyspy/blob/main/docs/forward.md#compare-clients-from-another-shell): leave the forward proxy running while you try requests from another shell.
- [Send one hostname to a local service](https://github.com/anaconda/proxyspy/blob/main/docs/forward.md#send-one-hostname-to-a-local-service): keep the URL the client expects, but let your development server answer.
- [Test behind a TLS-terminating firewall](https://github.com/anaconda/proxyspy/blob/main/docs/reverse.md): use the reverse proxy when the client must make a direct HTTPS connection with no proxy configured.
- [Test an error or timeout](https://github.com/anaconda/proxyspy/blob/main/docs/options.md): make a service return `503` or delay a handshake without changing the service itself.

For examples from real projects, see the [conda plugin, Worker, and certificate trust case studies](https://github.com/anaconda/proxyspy/blob/main/docs/case-studies.md).

The guides use proxyspy 0.3 or later and POSIX shell syntax. Run
`proxyspy --help` for the options available in your installation.

## Development

proxyspy is a [single Python file](https://github.com/anaconda/proxyspy/blob/main/proxyspy.py).
You can vendor it and run `python proxyspy.py` with Python 3.10+ and
`cryptography`, its only third-party runtime dependency. Please keep it that
way when contributing, and include tests for new behavior. From a checkout:

```sh
python -m pip install -e '.[test]'
python -m pytest -v
```

The original implementation and test suite were developed with Claude 3.5 and
3.7 Sonnet. Since then, contributors have used a range of models from several
vendors to develop proxyspy.
