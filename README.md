# HTTPS Debug Proxy

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

## Installation

The proxy is distributed as a single Python file `proxyspy.py`. To use it in your project:

1. Copy `proxyspy.py` into your repository
2. Ensure the `cryptography` package is available in your Python environment

That's it! The script is self-contained and ready to use.

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
./proxyspy.py [options] -- command [args...]
```

The tool starts a proxy server and then runs the specified command with appropriate proxy environment variables set.

### Options

- `--logfile FILE, -l FILE`: Write logs to FILE (default: stdout)
- `--port PORT, -p PORT`: Listen on PORT (default: 8080)
- `--keep-certs`: Keep certificates in current directory
- `--delay TIME`: Add TIME seconds delay to each connection
- `--return-code N, -r N`: Return status code N for all requests
- `--return-header H`: Add header H to responses (can repeat)
- `--return-data DATA`: Return DATA as response body

### Examples

Log all HTTPS requests to test.log:
```bash
./proxyspy.py --logfile test.log -- curl https://httpbin.org/ip
```

Return 404 for all requests with a half-second delay:
```bash
./proxyspy.py --return-code 404 --delay 0.5 -- python my_script.py
```

Return custom response with headers and body:
```bash
./proxyspy.py --return-code 200 \
              --return-header "Content-Type: application/json" \
              --return-data '{"status": "ok"}' \
              -- ./my_script.py
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

## Contributing

When submitting pull requests, please:
- Add tests for new features
- Ensure all tests pass
- Follow existing code style
- Do not add third-party dependencies beyond the required `cryptography` package
  - The proxy tester is designed to be a single, self-contained file
  - Additional dependencies make it harder for users to incorporate into their projects

## About This Project

This project was primarily developed through a series of conversations with Claude 3.5 Sonnet, an AI assistant from Anthropic (https://claude.ai). The majority of the code, including the test suite and GitHub Actions configuration, was written by Claude in response to requirements and refinements from human developers. This collaborative approach demonstrates how AI assistance can help create well-tested, maintainable code while adhering to strict dependency and design constraints.
