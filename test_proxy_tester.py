import os
import random
import shutil
import socket
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from subprocess import Popen

import psutil
import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ProxyTestHarness:
    """Test harness that manages the lifecycle of a proxy_tester.py instance."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.log_file = tmp_path / "test.log"
        self.proxy_process = None
        self.proxy_psutil = None
        # Get absolute path to proxy_tester.py
        self.script_path = str(Path(__file__).parent / "proxy_tester.py")
        self.old_env = dict(os.environ)

    def start_proxy(self, *extra_args):
        """Start the proxy with a long-running sleep process."""
        self.expected_port = random.randint(8080, 8099)
        self.keep_certs = "--keep-certs" in extra_args

        cmd = [
            "python",
            self.script_path,
            "--logfile",
            str(self.log_file),
            "--port",
            str(self.expected_port),
            *extra_args,
            "--",
            "sleep",
            "3600",  # Long-running process to keep proxy alive
        ]
        print(f"\nStarting proxy server: {' '.join(cmd)}")
        self.proxy_process = Popen(cmd)
        self.proxy_psutil = psutil.Process(self.proxy_process.pid)

        # Wait for and parse startup logs
        start_time = time.time()
        self.cert_dir = None
        self.port = None
        while time.time() - start_time < 5:  # 5 second timeout
            if os.path.exists(self.log_file):
                with open(self.log_file) as f:
                    lines = f.readlines()
                    for line in lines:
                        if "Certificate directory:" in line:
                            self.cert_dir = line.split(": ")[1].strip()
                        elif "Proxy server started on port" in line:
                            self.port = int(line.split("port")[1].strip())
                            # Found both pieces of info
                            if self.cert_dir is not None and self.port is not None:
                                assert self.port == self.expected_port, (
                                    f"Port mismatch: got {self.port}, "
                                    f"expected {self.expected_port}"
                                )
                                print(
                                    f"Proxy startup complete. Port: {self.port}, "
                                    f"Cert dir: {self.cert_dir}"
                                )
                                self.setup_environment()
                                return
            time.sleep(0.1)

        raise RuntimeError("Proxy failed to start within 5 seconds")

    def get_cert_path(self):
        """Return path to the CA certificate."""
        if self.cert_dir is None:
            raise RuntimeError("Proxy not started or certificate directory not found")
        return os.path.join(self.cert_dir, "cert.pem")

    def get_proxy_url(self):
        """Return the proxy URL."""
        if self.port is None:
            raise RuntimeError("Proxy not started or port not found")
        return f"http://localhost:{self.port}"

    def setup_environment(self):
        """Set environment variables for proxy and SSL verification."""
        proxy_url = self.get_proxy_url()
        cert_path = self.get_cert_path()

        # Set proxy environment variables
        os.environ["HTTP_PROXY"] = proxy_url
        os.environ["http_proxy"] = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url
        os.environ["https_proxy"] = proxy_url
        os.environ["NO_PROXY"] = ""
        os.environ["no_proxy"] = ""

        # Set certificate environment variables
        os.environ["CURL_CA_BUNDLE"] = cert_path
        os.environ["SSL_CERT_FILE"] = cert_path
        os.environ["REQUESTS_CA_BUNDLE"] = cert_path
        os.environ["CONDA_SSL_VERIFY"] = cert_path

    def restore_environment(self):
        os.environ.clear()
        os.environ.update(self.old_env)

    def stop_proxy(self):
        """Stop the proxy and its child processes."""
        if self.proxy_process:
            try:
                # Get all child processes
                children = self.proxy_psutil.children(recursive=True)
                if children:
                    print("\nTerminating child processes...")
                    # Terminate children first and wait for them
                    for child in children:
                        child.terminate()
                    psutil.wait_procs(children, timeout=3)
                    print("Child processes terminated")

                # Now wait for proxy to clean up and exit
                print("Waiting for proxy to exit...")
                self.proxy_process.wait(timeout=5)
                print("Proxy terminated successfully")
            except psutil.NoSuchProcess:
                print("Process already terminated")
            except psutil.TimeoutExpired:
                print("Proxy did not exit cleanly, forcing termination")
                if self.proxy_process.poll() is None:
                    self.proxy_process.terminate()
                    self.proxy_process.wait()
        self.restore_environment()

    def get_logs(self):
        """Return the contents of the log file as a list of lines."""
        with open(self.log_file) as f:
            return f.readlines()


@pytest.fixture
def proxy(tmp_path):
    """Fixture that provides a ProxyTestHarness and handles cleanup."""
    harness = ProxyTestHarness(tmp_path)
    try:
        yield harness
    finally:
        cert_dir = harness.cert_dir  # Save for verification
        harness.stop_proxy()
        # Verify cleanup
        if cert_dir and not harness.keep_certs:
            assert not os.path.exists(
                cert_dir
            ), f"Certificate directory not cleaned up: {cert_dir}"


@pytest.fixture(scope="module")
def session():
    """Construct a requests session object with retries."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    return session


def test_error_dns_nonexistent(proxy, session):
    """Test proxy handling of non-existent DNS names."""
    proxy.start_proxy()

    with pytest.raises(
        (requests.exceptions.ProxyError, requests.exceptions.ReadTimeout)
    ):
        session.get("https://httpbin.invalid/get", timeout=2.0)

    # Check logs
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Should see client connection and error
    assert any("[C->P] CONNECT httpbin.invalid:443" in line for line in logs)
    assert any("Socket error:" in line for line in logs)
    assert any("Connection closed" in line for line in logs)


def test_error_wrong_port(proxy, session):
    """Test proxy handling of connection to wrong port."""
    proxy.start_proxy()

    with pytest.raises(requests.exceptions.ConnectionError):
        # Port 81 is usually not running on httpbin.org
        session.get("https://httpbin.org:81/get", timeout=2.0)

    # Check logs
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Should see connection establishment but then timeout
    assert any("[C->P] CONNECT httpbin.org:81" in line for line in logs)
    assert any("[P->C] HTTP/1.0 200 Connection Established" in line for line in logs)
    assert any("[C<>P] SSL handshake completed" in line for line in logs)
    # Note: We don't see 'Connection closed' because the timeout doesn't trigger a clean closure


def test_error_no_listener(proxy, session):
    """Test proxy handling of connection to port with no listener."""
    proxy.start_proxy()

    # Find a port that's definitely not in use
    with socket.socket() as s:
        s.bind(("", 0))
        unused_port = s.getsockname()[1]

    with pytest.raises(
        (requests.exceptions.ProxyError, requests.exceptions.ReadTimeout)
    ):
        session.get(f"https://localhost:{unused_port}/get", timeout=2.0)

    # Check logs
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Should see attempt and connection refused
    assert any(f"[C->P] CONNECT localhost:{unused_port}" in line for line in logs)
    assert any("Socket error:" in line for line in logs)
    assert any("Connection closed" in line for line in logs)


def test_proxy_startup(proxy):
    """Test that proxy starts up and creates correct certificate directory and log files."""
    proxy.start_proxy()

    # Verify we got both key pieces of information
    assert proxy.cert_dir is not None, "Certificate directory not detected"
    assert proxy.port is not None, "Port number not detected"
    assert (
        proxy.port == proxy.expected_port
    ), f"Port mismatch: got {proxy.port}, expected {proxy.expected_port}"

    # Verify certificate exists
    cert_path = proxy.get_cert_path()
    assert os.path.exists(cert_path), f"Certificate file not found at {cert_path}"


def test_proxy_intercept(proxy, session):
    """Test that the proxy can intercept and return custom responses."""
    proxy.start_proxy(
        "--return-code",
        "418",  # I'm a teapot!
        "--return-header",
        "X-Test: Custom Header",
        "--return-data",
        '{"status": "intercepted"}',
    )

    # Make a request through the proxy - environment variables handle all config
    resp = session.get("https://httpbin.org/get")

    # Verify response was intercepted
    assert resp.status_code == 418
    assert resp.headers["X-Test"] == "Custom Header"
    assert resp.json() == {"status": "intercepted"}

    # Check logs to verify interception
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Verify SSL handshake completed (we're still terminating SSL)
    assert any("[C<>P] SSL handshake completed" in line for line in logs)

    # We should NOT see a server handshake since we're intercepting
    assert not any("[P<>S] SSL handshake completed" in line for line in logs)

    # Verify response was intercepted
    assert resp.status_code == 418
    assert resp.headers["X-Test"] == "Custom Header"
    assert resp.json() == {"status": "intercepted"}

    # Check logs to verify interception
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Verify SSL handshake completed (we're still terminating SSL)
    assert any("[C<>P] SSL handshake completed" in line for line in logs)

    # We should NOT see a server handshake since we're intercepting
    assert not any("[P<>S] SSL handshake completed" in line for line in logs)


def test_forwarding_response_body(proxy, session):
    """Test that forwarded responses handle response bodies correctly."""
    proxy.start_proxy()

    # Try bytes endpoint first with small payload
    print("\nTesting small binary response")
    response = session.get("https://httpbin.org/bytes/64")
    assert response.status_code == 200
    assert len(response.content) == 64
    print("Successfully received 64 bytes")

    # Check logs to get connection info
    logs = proxy.get_logs()

    # Group logs by connection ID
    connections = defaultdict(list)
    for line in logs:
        if "[" not in line:
            continue
        # Parse connection ID and timing
        cid = line.split("[")[1].split("/")[0]
        if cid.isdigit():
            connections[cid].append(line.strip())

    # Find the 64-byte request connection and analyze it
    small_request_cid = None
    for cid, lines in connections.items():
        if any("bytes/64" in line for line in lines):
            small_request_cid = cid
            print(f"\nSmall request (connection {cid}):")
            for line in lines:
                print(line)

    # Now try the larger response
    print("\nTesting 1KB binary response")
    response = session.get("https://httpbin.org/bytes/1024")
    assert response.status_code == 200
    print(f"Received {len(response.content)} bytes")
    assert len(response.content) == 1024

    # Get updated logs and find the 1KB request
    logs = proxy.get_logs()
    connections = defaultdict(list)
    for line in logs:
        if "[" not in line:
            continue
        cid = line.split("[")[1].split("/")[0]
        if cid.isdigit() and cid != small_request_cid:  # Skip the previous connection
            connections[cid].append(line.strip())

    # Find and analyze the 1KB request connection
    for cid, lines in connections.items():
        if any("bytes/1024" in line for line in lines):
            print(f"\nLarge request (connection {cid}):")
            for line in lines:
                print(line)


def test_intercept_response_body(proxy, session):
    """Test that intercepted responses handle response bodies correctly."""
    # Create a response body with various challenging content
    test_body = (
        # JSON-like content with embedded newlines and quotes
        '{\n  "key": "value\\nwith\\nlines",\n'
        '  "quotes": ""quoted string""\n}\n'
        # Header-like content that should be treated as body
        "Content-Type: application/json\r\n"
        "X-Custom-Header: value\r\n"
        # Blank line that shouldn't act as header delimiter
        "\r\n"
        # More data after blank line
        "Final line of response"
    )

    proxy.start_proxy(
        "--return-code",
        "200",
        "--return-header",
        "Content-Type: text/plain",
        # Let the proxy calculate and add Content-Length
        "--return-data",
        test_body,
    )

    response = session.get("https://httpbin.org/get")

    # Basic response verification
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/plain"
    assert int(response.headers["Content-Length"]) == len(
        test_body
    )  # Verify length matches

    # The response body should match exactly, byte for byte
    assert response.text == test_body

    # Check logs
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Find the intercepted response in logs
    # It should appear as one complete chunk in the log
    response_lines = [l for l in logs if "[P->C]" in l]
    assert len(response_lines) > 0, "No response found in logs"

    # Verify response was intercepted (no server connection)
    assert any("[C<>P] SSL handshake completed" in line for line in logs)
    assert not any("[P<>S] SSL handshake completed" in line for line in logs)


def test_intercept_headers(proxy, session):
    """Test that intercepted responses handle headers correctly."""
    proxy.start_proxy(
        "--return-code",
        "200",
        "--return-header",
        "Content-Type: application/json",
        "--return-header",
        "X-Custom-String: Hello, World!",
        "--return-header",
        "X-Custom-Empty:",  # Empty value
        "--return-header",
        "X-Custom-Special: Hello: world; something=value",  # Special chars
        "--return-header",
        "X-Custom-Long: " + "x" * 1000,  # Long value
        "--return-header",
        "Set-Cookie: cookie1=value1",  # First cookie
        "--return-header",
        "Set-Cookie: cookie2=value2",  # Second cookie
        "--return-data",
        '{"status": "ok"}',
    )

    response = session.get("https://httpbin.org/get")

    # Basic response verification
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    # Headers should exist and have correct values
    assert response.headers["Content-Type"] == "application/json"
    assert response.headers["X-Custom-String"] == "Hello, World!"
    assert response.headers["X-Custom-Empty"] == ""
    assert response.headers["X-Custom-Special"] == "Hello: world; something=value"
    assert response.headers["X-Custom-Long"] == "x" * 1000

    # Multiple Set-Cookie headers should be preserved separately
    assert len(response.cookies) == 2
    assert response.cookies["cookie1"] == "value1"
    assert response.cookies["cookie2"] == "value2"

    # Check logs
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Verify that all headers appear in the proxy's output log
    assert any("Content-Type: application/json" in line for line in logs)
    assert any("X-Custom-String: Hello, World!" in line for line in logs)
    assert any("X-Custom-Empty:" in line for line in logs)
    assert any(
        "X-Custom-Special: Hello: world; something=value" in line for line in logs
    )
    assert any("Set-Cookie: cookie1=value1" in line for line in logs)
    assert any("Set-Cookie: cookie2=value2" in line for line in logs)

    # Verify response was intercepted
    assert any("[C<>P] SSL handshake completed" in line for line in logs)
    assert not any("[P<>S] SSL handshake completed" in line for line in logs)


def test_keep_certs(proxy, session):
    """Test that --keep-certs option keeps certificates in current directory."""
    # Start in a clean temp directory
    orig_dir = os.getcwd()
    temp_dir = proxy.tmp_path / "keep_certs_test"
    temp_dir.mkdir()
    os.chdir(temp_dir)

    try:
        # Start proxy with --keep-certs
        proxy.start_proxy("--keep-certs")

        # Verify CA cert files exist in current directory
        ca_cert = Path("cert.pem")
        ca_key = Path("key.pem")
        assert ca_cert.exists(), "CA certificate not found"
        assert ca_key.exists(), "CA key not found"

        session.get("https://httpbin.org/get")

        # Verify host cert files exist
        host_cert = Path("httpbin.org-cert.pem")
        host_key = Path("httpbin.org-key.pem")
        assert host_cert.exists(), "Host certificate not found"
        assert host_key.exists(), "Host key not found"

        # Stop proxy and verify files still exist
        proxy.stop_proxy()
        assert ca_cert.exists(), "CA certificate removed"
        assert ca_key.exists(), "CA key removed"
        assert host_cert.exists(), "Host certificate removed"
        assert host_key.exists(), "Host key removed"

    finally:
        # Clean up and restore directory
        os.chdir(orig_dir)
        shutil.rmtree(temp_dir)


def test_proxy_delay(proxy, session):
    """Test that the --delay option enforces connection delays."""
    delay = 0.25
    proxy.start_proxy("--delay", str(delay))

    # Make a request through the proxy using environment settings
    resp = session.get("https://httpbin.org/get")
    assert resp.status_code == 200

    # Check logs for delay enforcement
    logs = proxy.get_logs()
    assert any(f"Enforcing {delay}s delay" in line for line in logs)
    assert any("End of connection delay" in line for line in logs)

    # Verify timing from logs
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Find all delay-related lines
    delay_lines = [l for l in logs if "delay" in l]
    print("\nDelay lines:")
    for line in delay_lines:
        print(line.strip())

    enforcing_lines = [l for l in delay_lines if "Enforcing" in l]
    print("\nEnforcing lines:")
    for line in enforcing_lines:
        print(line.strip())

    if enforcing_lines:
        end_lines = [l for l in delay_lines if "End of" in l]
        if end_lines:
            end_time = float(
                end_lines[0].split("/")[2].split("]")[0]
            )  # Total elapsed at end
            print(f"\nTotal elapsed at delay end: {end_time:.3f}s")
            # Verify we waited at least the requested delay
            assert end_time >= delay, f"Delay too short: {end_time:.3f}s < {delay}s"
        else:
            pytest.fail("No 'End of delay' message found in logs")


def test_concurrent_connections(proxy):
    """Test that the proxy can handle multiple simultaneous connections."""
    proxy.start_proxy()

    def make_request(i):
        # Create session with retry strategy
        session = requests.Session()
        retry_strategy = Retry(
            total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)

        url = f"https://httpbin.org/get?ndx={i}"
        try:
            resp = session.get(url, timeout=5.0)
            return resp.status_code, i
        except requests.exceptions.RequestException as e:
            print(f"\nRequest {i} failed: {str(e)}")
            return None, i

    # Make 4 concurrent requests
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(make_request, i) for i in range(4)]
        results = [f.result() for f in futures]

    # Check logs before checking results
    logs = proxy.get_logs()
    print("\nAll logs:")
    for line in logs:
        print(line.strip())

    # Extract connection IDs and build timeline for each
    connections = defaultdict(list)
    for line in logs:
        if "[" not in line:  # Skip non-connection log lines
            continue
        # Parse connection ID and timing
        cid = line.split("[")[1].split("/")[0]
        if cid.isdigit():  # Only track numbered connections
            connections[cid].append(line.strip())

    # Analyze results and connections
    successful_requests = [r for r in results if r[0] is not None]
    failed_requests = [r for r in results if r[0] is None]

    print(f"\nSuccessful requests: {len(successful_requests)}")
    print(f"Failed requests: {len(failed_requests)}")
    print(f"Total connections seen: {len(connections)}")

    # Verify basic expectations
    assert (
        len(connections) >= 4
    ), f"Expected at least 4 connections, got {len(connections)}"
    assert len(successful_requests) > 0, "Expected at least some successful requests"

    # For successful connections, verify complete flow
    for cid, lines in connections.items():
        connect_lines = [l for l in lines if "[C->P] CONNECT" in l]
        if not connect_lines:
            continue  # Skip partial connections

        assert any(
            "[C<>P] SSL handshake completed" in l for l in lines
        ), f"Connection {cid} missing client handshake"
        assert any(
            "[P<>S] SSL handshake completed" in l for l in lines
        ), f"Connection {cid} missing server handshake"
