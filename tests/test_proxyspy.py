import os
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
from requests.exceptions import ConnectionError, ProxyError, ReadTimeout, RequestException
from urllib3.util.retry import MaxRetryError, Retry

EXCEPTIONS = ConnectionError, ProxyError, ReadTimeout, RequestException, MaxRetryError


def find_proxyspy():
    """Locate the proxyspy script in development or installed environments."""
    # First look for proxyspy.py in development location
    script_path = Path(__file__).parent.parent / "proxyspy.py"
    if script_path.exists():
        return str(script_path)

    # Then check if proxyspy is installed in PATH
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        # Look for either 'proxyspy' or 'proxyspy.exe' on Windows
        for name in ["proxyspy", "proxyspy.exe"]:
            candidate = os.path.join(path_dir, name)
            if os.path.isfile(candidate):
                return candidate

    raise FileNotFoundError(
        "Could not find the proxyspy script. "
        "It should either be installed in PATH or present in development directory."
    )


class ProxyTestHarness:
    """Test harness that manages the lifecycle of a proxyspy.py instance."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.log_file = tmp_path / "test.log"
        self.proxy_process = None
        self.proxy_psutil = None
        self.script_path = find_proxyspy()
        self.old_env = dict(os.environ)
        self.logs = None

    def start_proxy(self, *extra_args):
        """Start the proxy with a long-running sleep process."""
        # Find an available port by trying until we succeed

        # Default to port 0 (auto-selection) if no port specified
        self.expected_port = 0
        for i, arg in enumerate(extra_args):
            if arg == "--port" and i + 1 < len(extra_args):
                self.expected_port = int(extra_args[i + 1])
                break

        self.keep_certs = "--keep-certs" in extra_args

        # For development testing, use python interpreter
        if isinstance(self.script_path, Path) or self.script_path.endswith(".py"):
            cmd = ["python", str(self.script_path)]
        # For installed package, just run the entry point directly
        else:
            cmd = [str(self.script_path)]

        if "--logfile" not in extra_args:
            cmd.extend(("--logfile", str(self.log_file)))
        if "--port" not in extra_args:
            cmd.extend(("--port", "0"))
        cmd.extend(extra_args)
        # Long-running process to keep proxy alive
        cmd.extend(("--", "sleep", "3600"))
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
                                if self.expected_port != 0:
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
        if hasattr(self, "logs"):
            self.logs = None

        if self.proxy_process:
            try:
                # First terminate all child processes
                children = self.proxy_psutil.children(recursive=True)
                sleep_processes = [
                    p
                    for p in children
                    if "sleep" in p.name().lower() or "timeout" in p.name().lower()  # Unix
                ]  # Windows equivalent
                if sleep_processes:
                    print("\nTerminating child processes...")
                    for child in sleep_processes:
                        try:
                            child.terminate()
                        except psutil.NoSuchProcess:
                            pass
                    psutil.wait_procs(sleep_processes, timeout=3)
                    print("Child processes terminated")

                # Now wait for proxy to initiate its own shutdown
                print("Waiting for proxy to exit gracefully...")
                for _ in range(30):  # 3 seconds total
                    if self.proxy_process.poll() is not None:
                        print("Proxy exited cleanly")
                        self.restore_environment()
                        # On Windows, sleep briefly to allow file handles to be released
                        if os.name == "nt":
                            time.sleep(0.5)
                        return True
                    time.sleep(0.1)

                # If we get here, proxy failed to shut down on its own
                print("Proxy failed to exit gracefully, terminating")
                self.proxy_process.terminate()
                self.proxy_process.wait(timeout=3)
                return False

            except (psutil.NoSuchProcess, psutil.TimeoutExpired) as e:
                print(f"Process cleanup error: {e}")
                if self.proxy_process.poll() is None:
                    self.proxy_process.kill()
                    self.proxy_process.wait()
                return False

            finally:
                self.restore_environment()

    def get_logs(self, force=False):
        """Return the contents of the log file as a list of lines."""
        if force or self.logs is None:
            with open(self.log_file) as f:
                self.logs = f.readlines()
            print("\nAll logs:")
            for line in self.logs:
                print(line.strip())
        return self.logs

    def get_connections(self):
        """Return dict of connections and their log lines."""
        connections = defaultdict(list)
        for line in self.get_logs():
            if "[" in line:
                cid = line.split("[")[1].split("/")[0]
                if cid.isdigit():
                    connections[cid].append(line.strip())
        print(f"Total connections seen: {len(connections)}")
        return connections

    def verify_header(self, response, name, value):
        """Verify a header exists in both response and logs."""
        assert response.headers[name] == value
        self.assert_log_contains(f"{name}: {value}")

    def assert_log_contains(self, pattern):
        """Assert logs contain a line matching pattern."""
        assert any(pattern in line for line in self.get_logs())

    def assert_intercepted(self):
        """Assert logs show interception (client SSL but no server SSL)."""
        self.assert_log_contains("[C<>P] SSL handshake completed")
        assert not any("[P<>S] SSL handshake completed" in line for line in self.get_logs())


@pytest.fixture
def proxy(tmp_path):
    """Fixture that provides a ProxyTestHarness and handles cleanup."""
    harness = ProxyTestHarness(tmp_path)
    try:
        yield harness
    finally:
        cert_dir = harness.cert_dir  # Save for verification
        clean_shutdown = harness.stop_proxy()
        # Only verify directory cleanup if we had a clean shutdown
        if clean_shutdown and cert_dir and not harness.keep_certs:
            assert not os.path.exists(cert_dir), f"Certificate directory not cleaned up: {cert_dir}"


def _get_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=5, backoff_factor=0.5, backoff_jitter=0.5, status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    return session


@pytest.fixture(scope="module")
def session():
    """Construct a requests session object with retries."""
    return _get_session()


def test_error_dns_nonexistent(proxy, session):
    """Test proxy handling of non-existent DNS names."""
    proxy.start_proxy()

    with pytest.raises(EXCEPTIONS):
        session.get("https://httpbin.invalid/get", timeout=2.0)

    # Should see client connection and error
    proxy.assert_log_contains("[C->P] CONNECT httpbin.invalid:443")
    proxy.assert_log_contains("Socket error:")
    proxy.assert_log_contains("Connection closed")


def test_error_wrong_port(proxy, session):
    """Test proxy handling of connection to wrong port."""
    proxy.start_proxy()

    with pytest.raises(EXCEPTIONS):
        # Port 81 is usually not running on httpbin.org
        session.get("https://httpbin.org:81/get", timeout=2.0)

    # Should see connection establishment but then timeout
    proxy.assert_log_contains("[C->P] CONNECT httpbin.org:81")
    proxy.assert_log_contains("[P->C] HTTP/1.0 200 Connection Established")
    proxy.assert_log_contains("[C<>P] SSL handshake completed")
    # Note: We don't see 'Connection closed' because the timeout doesn't trigger a clean closure


def test_error_no_listener(proxy, session):
    """Test proxy handling of connection to port with no listener."""
    proxy.start_proxy()

    # Find a port that's definitely not in use
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        unused_port = s.getsockname()[1]

    with pytest.raises(EXCEPTIONS):
        session.get(f"https://localhost:{unused_port}/get", timeout=2.0)

    # Should see attempt and connection refused
    proxy.assert_log_contains(f"[C->P] CONNECT localhost:{unused_port}")
    proxy.assert_log_contains("Socket error:")
    proxy.assert_log_contains("Connection closed")


def test_proxy_startup(proxy):
    """Test that proxy starts up and creates correct certificate directory and log files."""
    proxy.start_proxy()

    # Verify we got both key pieces of information
    assert proxy.cert_dir is not None, "Certificate directory not detected"
    assert proxy.port is not None, "Port number not detected"

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
    proxy.verify_header(resp, "X-Test", "Custom Header")
    assert resp.json() == {"status": "intercepted"}

    proxy.assert_intercepted()


def test_forwarding_response_body(proxy, session):
    """Test that forwarded responses handle response bodies correctly."""
    proxy.start_proxy()

    # Try bytes endpoint first with small payload
    print("\nTesting small binary response")
    response = session.get("https://httpbin.org/bytes/64")
    assert response.status_code == 200
    assert len(response.content) == 64
    print("Successfully received 64 bytes")

    # Now try the larger response
    print("\nTesting 1KB binary response")
    response = session.get("https://httpbin.org/bytes/1024")
    assert response.status_code == 200
    print(f"Received {len(response.content)} bytes")
    assert len(response.content) == 1024


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
    proxy.verify_header(response, "Content-Type", "text/plain")
    assert int(response.headers["Content-Length"]) == len(test_body)  # Verify length matches

    # The response body should match exactly, byte for byte
    assert response.text == test_body

    # Check logs
    logs = proxy.get_logs()

    # Find the intercepted response in logs
    # It should appear as one complete chunk in the log
    response_lines = [l for l in logs if "[P->C]" in l]
    assert len(response_lines) > 0, "No response found in logs"

    # Verify response was intercepted (no server connection)
    proxy.assert_intercepted()


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
    proxy.verify_header(response, "Content-Type", "application/json")
    proxy.verify_header(response, "X-Custom-String", "Hello, World!")
    proxy.verify_header(response, "X-Custom-Empty", "")
    proxy.verify_header(response, "X-Custom-Special", "Hello: world; something=value")
    proxy.verify_header(response, "X-Custom-Long", "x" * 1000)

    # Multiple Set-Cookie headers should be preserved separately
    assert len(response.cookies) == 2
    assert response.cookies["cookie1"] == "value1"
    assert response.cookies["cookie2"] == "value2"
    proxy.assert_log_contains("Set-Cookie: cookie1=value1")
    proxy.assert_log_contains("Set-Cookie: cookie2=value2")

    # Verify response was intercepted
    proxy.assert_intercepted()


def test_intercept_pattern(proxy, session):
    """Test that the proxy only intercepts requests matching the specified patterns."""
    proxy.start_proxy(
        "--return-code", "418",
        "--return-header", "X-Test: Pattern Match",
        "--return-data", '{"status": "intercepted by pattern"}',
        "--intercept-pattern", "httpbin.org",
        "--intercept-pattern", "example.com"
    )

    # Request 1: Should match first pattern
    resp_match1 = session.get("https://httpbin.org/get")
    assert resp_match1.status_code == 418
    proxy.verify_header(resp_match1, "X-Test", "Pattern Match")
    assert resp_match1.json() == {"status": "intercepted by pattern"}
    
    # Force refresh logs and verify first request
    proxy.get_logs(force=True)
    assert any("httpbin.org matches intercept pattern" in line for line in proxy.get_logs())
    
    # Request 2: Should match second pattern
    resp_match2 = session.get("https://example.com/")
    assert resp_match2.status_code == 418
    proxy.verify_header(resp_match2, "X-Test", "Pattern Match")
    assert resp_match2.json() == {"status": "intercepted by pattern"}
    
    # Force refresh logs and verify second request
    proxy.get_logs(force=True)
    assert any("example.com matches intercept pattern" in line for line in proxy.get_logs())
    
    # Request 3: Should not match any pattern
    resp_nomatch = session.get("https://example.org/")
    assert resp_nomatch.status_code == 200
    assert "Example Domain" in resp_nomatch.text
    
    # Force refresh logs and verify third request
    logs = proxy.get_logs(force=True)
    assert any("example.org does not match any intercept patterns" in line for line in logs)
    
    # Check connections to verify SSL handshakes
    connections = proxy.get_connections()
    
    # Helper function to check if a connection was intercepted or forwarded
    def find_connection(domain):
        for cid, lines in connections.items():
            if any(domain in line for line in lines):
                return lines
        return None
    
    # Verify both matching connections were intercepted (client SSL but no server SSL)
    for domain in ["httpbin.org", "example.com"]:
        conn_lines = find_connection(domain)
        assert conn_lines is not None, f"Connection for {domain} not found"
        assert any("[C<>P] SSL handshake completed" in line for line in conn_lines)
        assert not any("[P<>S] SSL handshake completed" in line for line in conn_lines)
    
    # Verify non-matching connection was forwarded (both client and server SSL)
    nonmatch_lines = find_connection("example.org")
    assert nonmatch_lines is not None, "Connection for example.org not found"
    assert any("[C<>P] SSL handshake completed" in line for line in nonmatch_lines)
    assert any("[P<>S] SSL handshake completed" in line for line in nonmatch_lines)


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
    proxy.start_proxy("--delay", str(delay), "--return-code", str(200))

    # Make a request through the proxy using environment settings
    resp = session.get("https://httpbin.org/get")
    assert resp.status_code == 200

    # Check logs for delay enforcement
    logs = proxy.get_logs()
    proxy.assert_log_contains(f"Enforcing {delay}s delay")
    proxy.assert_log_contains("End of connection delay")

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
            end_time = float(end_lines[0].split("/")[2].split("]")[0])  # Total elapsed at end
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
        url = f"https://httpbin.org/get?ndx={i}"
        try:
            resp = _get_session().get(url, timeout=5.0)
            return resp.status_code, i
        except RequestException as e:
            print(f"\nRequest {i} failed: {str(e)}")
            return None, i

    # Make 4 concurrent requests
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(make_request, i) for i in range(4)]
        results = [f.result() for f in futures]

    # Analyze results and connections
    successful_requests = [r for r in results if r[0] is not None]
    failed_requests = [r for r in results if r[0] is None]
    print(f"Successful requests: {len(successful_requests)}")
    print(f"Failed requests: {len(failed_requests)}")

    # Group logs by connection
    connections = proxy.get_connections()
    assert len(connections) >= 4, f"Expected at least 4 connections, got {len(connections)}"
    assert len(successful_requests) > 0, "Expected at least some successful requests"

    # For successful connections, verify complete flow
    for cid, lines in connections.items():
        connect_lines = [l for l in lines if "[C->P] CONNECT" in l]
        if connect_lines:  # Skip partial connections
            assert any(
                "[C<>P] SSL handshake completed" in l for l in lines
            ), f"Connection {cid} missing client handshake"
            assert any(
                "[P<>S] SSL handshake completed" in l for l in lines
            ), f"Connection {cid} missing server handshake"


def test_sequential_proxy_starts(tmp_path):
    """Test that the proxy can be started multiple times in sequence."""
    test_iterations = 3
    ports_used = []

    # Test multiple sequential startups with auto-selection
    for i in range(test_iterations):
        test_dir = tmp_path / f"auto_{i}"
        test_dir.mkdir(exist_ok=True)
        harness = ProxyTestHarness(test_dir)
        try:
            # Use auto port selection
            harness.start_proxy("--return-code", "404")
            assert harness.port > 0, "No valid port was selected"
            ports_used.append(harness.port)
            print(f"Auto-selected port {harness.port} succeeded")

            # Make a simple request to ensure proxy is working
            session = _get_session()
            try:
                response = session.get("https://httpbin.org/get", timeout=2.0)
                assert response.status_code == 404, "Expected 404 response"
                print(f"Request test passed with status {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Request resulted in expected exception: {e}")
        finally:
            harness.stop_proxy()

    # Verify we got different ports
    print(f"Ports used: {ports_used}")
    assert len(set(ports_used)) > 1, "Auto-port selection didn't rotate ports"
