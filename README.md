# HTTPS Debug Proxy

[![Build and Test](https://github.com/anaconda/proxyspy/actions/workflows/main.yaml/badge.svg)](https://github.com/anaconda/proxyspy/actions/workflows/main.yaml)
[![Latest Release](https://img.shields.io/github/v/release/anaconda/proxyspy?include_prereleases)](https://github.com/anaconda/proxyspy/releases/latest)
[![PyPI version](https://img.shields.io/pypi/v/proxyspy.svg)](https://pypi.org/project/proxyspy/)
[![Conda Version](https://img.shields.io/conda/v/mcg/proxyspy)](https://anaconda.org/mcg/proxyspy)

A debugging proxy that can log or intercept HTTPS requests. This tool can be used to:

- Monitor HTTPS traffic from applications
- Debug SSL/TLS issues
- Test applications against specific HTTP responses
- Simulate network delays

## Features

- Full HTTPS request/response logging
- Custom response injection
- Automatic certificate generation
- Connection delays for testing
- Concurrent connection support
- Binary data handling
- Automatic port selection

## Installation

ProxySpy is available on both Conda-Forge and PyPi:

```bash
conda install conda-forge::proxyspy  # or...
pip install proxyspy
```

Installing it this way ensures that its `cryptography` dependency is also
available, and add the `proxyspy` command to your `PATH` when this Python
environment is activated.

This utility has been deliberately designed to function as a single-file
Python script that depends only upon the standard Python 3 library and the
`cryptography` package. For that reason, you can also vendor the script
directly into your work environment if you wish.

1. Copy `proxyspy.py` directly into your project.
   [Here](https://raw.githubusercontent.com/anaconda/proxyspy/refs/heads/main/proxyspy.py)
   is a direct download link to the latest version of the script.
2. Ensure the `cryptography` package is available in your Python environment:
   ```
   conda install cryptography  # or...
   pip install cryptography
   ```

## Development Requirements

To develop or test the proxy itself, additional packages are required:

```bash
conda install --file requirements.txt
```

This will install:
- cryptography (required for proxy operation)
- requests (for tests)
- pytest (for running tests)

## Usage

```bash
proxyspy [options] -- command [args...]            # Installed as a package
python proxyspy.py [options] -- command [args...]  # Direct access
```

The tool starts a proxy server and then runs the specified command with appropriate proxy environment variables set.

### Options

- `--logfile FILE, -l FILE`: Write logs to FILE (default: stdout)
- `--port PORT, -p PORT`: Listen on PORT (default: auto-select)
- `--keep-certs`: Keep certificates in current directory
- `--delay TIME`: Add TIME seconds delay to each connection
- `--return-code N, -r N`: Return status code N for all requests
- `--return-header H`: Add header H to responses (can repeat)
- `--return-data DATA`: Return DATA as response body
- `--intercept-host HOST`: Only intercept requests to HOST (can repeat)

### Examples

Log all HTTPS requests to test.log:

```bash
proxyspy --logfile test.log -- curl https://httpbingo.org/ip
```

Return 404 for all requests with a half-second delay:

```bash
proxyspy --return-code 404 --delay 0.5 -- python my_script.py
```

Return custom response with headers and body:

```bash
proxyspy --return-code 200 \
         --return-header "Content-Type: application/json" \
         --return-data '{"status": "ok"}' \
         -- ./my_script.py
```

Use specific port instead of auto-selection:

```bash
proxyspy.py --port 8888 -- curl https://httpbingo.org/ip
```

Intercept only requests to specific domains:

```bash
proxyspy --return-code 404 \
         --intercept-host "conda.anaconda.org" \
         --intercept-host "repo.anaconda.com" \
         -- python conda_script.py
```

## How It Works

The proxy operates in two modes and can optionally add delays to any connection:

### Forwarding Mode (default)
- Creates a CA certificate and per-host certificates
- Establishes SSL tunnels to requested hosts
- Logs all traffic passing through

### Interception Mode
- Activated by specifying any of: --return-code, --return-data, --return-header
- Returns custom responses instead of connecting to servers
- Useful for testing application behavior

### Connection Delays
- Optional delay can be added to any connection in either mode
- Delay occurs after connection but before SSL handshake
- Useful for testing timeout and connection handling

### Port Selection
- By default, the proxy automatically selects an available port
- This prevents socket reuse issues and allows running multiple instances
- A specific port can be chosen with the --port option

## Development

Run tests:
```bash
pytest -v
```

The test suite covers:
- Basic forwarding
- Response interception
- Binary data handling
- Connection delays
- Error conditions
- Sequential proxy starts

## Contributing

When submitting pull requests, please:
- Add tests for new features
- Ensure all tests pass
- Follow existing code style
- Do not add third-party dependencies beyond the required `cryptography` package
  - The proxy tester is designed to be a single, self-contained file
  - Additional dependencies make it harder for users to incorporate into their projects

## About This Project

This project was primarily developed through a series of conversations with Claude 3.5 and 3.7 Sonnet, an AI assistant from Anthropic (https://claude.ai). The majority of the code, including the test suite and GitHub Actions configuration, was written by Claude in response to requirements and refinements from human developers. This collaborative approach demonstrates how AI assistance can help create well-tested, maintainable code while adhering to strict dependency and design constraints.
