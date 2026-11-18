import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from subprocess import Popen
from threading import Thread

import psutil
import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, ProxyError, ReadTimeout, RequestException
from urllib3.util.retry import MaxRetryError, Retry

import proxyspy

EXCEPTIONS = ConnectionError, ProxyError, ReadTimeout, RequestException, MaxRetryError

# Hostname the forwarding tests use for the in-process origin. It resolves to
# loopback without DNS and the origin's certificate is valid for it.
ORIGIN_HOST = "localhost"

# Hostname the --map tests send through the proxy. It never resolves (.invalid),
# so a passing test proves the traffic went to the mapped upstream and not to a
# real host. The origin's certificate is also valid for it, so an https:// map
# can still verify the upstream against the original name.
MAPPED_HOST = "proxyspy-mapped.invalid"


def _robust_rmtree(path, attempts=5):
    """shutil.rmtree that tolerates Windows' lag in releasing file/dir handles
    held by a just-terminated subprocess (WinError 32)."""
    for attempt in range(attempts):
        try:
            shutil.rmtree(path)
            return
        except (PermissionError, OSError):
            if attempt == attempts - 1:
                raise
            time.sleep(0.5 * (attempt + 1))


def _make_origin_cert(cert_dir):
    """Generate a self-signed cert/key valid for ORIGIN_HOST and 127.0.0.1.

    The cert serves double duty: it is the origin's server certificate and,
    because it is self-signed, its own CA file. Pointing the proxy's
    SSL_CERT_FILE at it lets proxyspy verify the origin upstream.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ORIGIN_HOST)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(ORIGIN_HOST),
                    x509.DNSName(MAPPED_HOST),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(cert_dir, "origin-cert.pem")
    key_path = os.path.join(cert_dir, "origin-key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


class _OriginHandler(BaseHTTPRequestHandler):
    """Minimal stand-in for the httpbin endpoints the tests exercise:
    /get (JSON echo), /bytes/<n> (n bytes), and ?ndx=N query echo on /get.
    The /get echo also reports whether the request arrived over TLS, so the
    --map tests can tell which origin served it."""

    def log_message(self, *args):
        pass  # keep test output quiet

    def _echo(self, body_length=None):
        """JSON echo of the request. header_list preserves duplicates (which
        the headers dict collapses); peer_port identifies the upstream TCP
        connection, so tests can confirm keep-alive reuse."""
        body = json.dumps(
            {
                "url": self.path,
                "headers": dict(self.headers),
                "header_list": list(self.headers.items()),
                "tls": isinstance(self.connection, ssl.SSLSocket),
                "peer_port": self.client_address[1],
                "body_length": body_length,
            }
        ).encode()
        self._respond(200, body, "application/json")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self._echo(body_length=len(self.rfile.read(length)))

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/get":
            self._echo()
        elif path.startswith("/bytes/"):
            try:
                n = int(path.rsplit("/", 1)[1])
            except ValueError:
                self._respond(404, b"bad byte count", "text/plain")
                return
            self._respond(200, bytes(n), "application/octet-stream")
        else:
            self._respond(404, b"not found", "text/plain")

    def _respond(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _KeepAliveOriginHandler(_OriginHandler):
    """HTTP/1.1 variant that keeps connections open between requests."""

    protocol_version = "HTTP/1.1"


class LocalOrigin:
    """In-process HTTPS origin so the forwarding tests don't depend on a public
    server. Cross-platform and available to local `pytest` runs. With
    tls=False it serves plain HTTP instead (a stand-in for a local dev server
    such as `wrangler dev`). With keepalive=True it speaks HTTP/1.1 and keeps
    connections open between requests."""

    def __init__(self, cert_dir, tls=True, keepalive=False):
        handler = _KeepAliveOriginHandler if keepalive else _OriginHandler
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        # Don't let stop() wait on handler threads parked on an idle keep-alive
        # connection.
        self.server.block_on_close = False
        if tls:
            self.cert_path, self.key_path = _make_origin_cert(cert_dir)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cert_path, self.key_path)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self):
        return f"https://{ORIGIN_HOST}:{self.port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def origin(tmp_path):
    """A running in-process HTTPS origin; yields the LocalOrigin instance."""
    server = LocalOrigin(str(tmp_path))
    try:
        yield server
    finally:
        server.stop()


def _capture_sni(origin):
    """Record the SNI name of each TLS connection to origin. Python sends no
    SNI for an IP address, so this distinguishes verifying against the
    original host name from dialing (and verifying) the mapped address."""
    names = []
    origin.server.socket.context.sni_callback = lambda sock, name, ctx: names.append(name)
    return names


@pytest.fixture
def plain_origin(tmp_path):
    """A running in-process plain-HTTP origin; yields the LocalOrigin instance."""
    server = LocalOrigin(str(tmp_path), tls=False)
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def keepalive_origin(tmp_path):
    """A running in-process plain-HTTP/1.1 keep-alive origin."""
    server = LocalOrigin(str(tmp_path), tls=False, keepalive=True)
    try:
        yield server
    finally:
        server.stop()


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

    def start_proxy(self, *extra_args, trust=None):
        """Start the proxy with a long-running sleep process.

        trust: optional path to a CA/cert file the proxy process should trust
        for upstream verification (via SSL_CERT_FILE), e.g. a LocalOrigin's
        certificate so the proxy can forward to the in-process origin.
        """
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
        cmd.extend(("--debug", "--", "sleep", "3600"))
        print(f"\nStarting proxy server: {' '.join(cmd)}")
        env = os.environ.copy()
        if trust:
            # The proxy verifies upstream certs with create_default_context();
            # SSL_CERT_FILE makes it trust the in-process origin's certificate.
            env["SSL_CERT_FILE"] = str(trust)
        self.proxy_process = Popen(cmd, env=env)
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
        # Port 81 is usually not running on httpbingo.org
        session.get("https://httpbingo.org:81/get", timeout=2.0)

    # Should see connection establishment but then timeout
    proxy.assert_log_contains("[C->P] CONNECT httpbingo.org:81")
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
    resp = session.get("https://httpbingo.org/get")

    # Verify response was intercepted
    assert resp.status_code == 418
    proxy.verify_header(resp, "X-Test", "Custom Header")
    assert resp.json() == {"status": "intercepted"}

    proxy.assert_intercepted()


def test_forwarding_response_body(proxy, session, origin):
    """Test that forwarded responses handle response bodies correctly."""
    proxy.start_proxy(trust=origin.cert_path)

    # Try bytes endpoint first with small payload
    print("\nTesting small binary response")
    response = session.get(f"{origin.base_url}/bytes/64")
    assert response.status_code == 200
    assert len(response.content) == 64
    print("Successfully received 64 bytes")

    # Now try the larger response
    print("\nTesting 1KB binary response")
    response = session.get(f"{origin.base_url}/bytes/1024")
    assert response.status_code == 200
    print(f"Received {len(response.content)} bytes")
    assert len(response.content) == 1024


def test_prepare_hosts(proxy):
    proxy.start_proxy(
        "--intercept-host",
        "example.org",
        "--intercept-host",
        "example.com",
        "--prepare-host",
        "httpbingo.org",
        "--prepare-host",
        "httpbin.com",
    )
    for host in ("example.org", "example.com", "httpbingo.org", "httpbin.com"):
        proxy.assert_log_contains("Requested certificate for " + host)


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

    response = session.get("https://httpbingo.org/get")

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

    response = session.get("https://httpbingo.org/get")

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


def test_intercept_hosts(proxy, session, origin):
    """Test that the proxy only intercepts requests matching the specified patterns.

    The intercepted hosts (example.com/.org) are never contacted upstream, so
    they need not be real; only the single non-intercepted control is forwarded
    to the in-process origin, so the test has no public-network dependency.
    """
    proxy.start_proxy(
        "--return-code",
        "418",
        "--return-header",
        "X-Test: Host Match",
        "--return-data",
        '{"status": "intercepted by host list"}',
        "--intercept-host",
        "example.com",
        "--intercept-host",
        "example.org",
        trust=origin.cert_path,
    )

    # Requests 1 & 2: hosts in the intercept list -> canned response, no upstream
    for host in ("example.com", "example.org"):
        resp_match = session.get(f"https://{host}/")
        assert resp_match.status_code == 418
        proxy.verify_header(resp_match, "X-Test", "Host Match")
        assert resp_match.json() == {"status": "intercepted by host list"}
        proxy.get_logs(force=True)
        assert any(f"{host} found in intercept list" in line for line in proxy.get_logs())

    # Request 3: host not in the intercept list -> forwarded to the origin
    resp_nomatch = session.get(f"{origin.base_url}/get")
    assert resp_nomatch.status_code == 200

    # Force refresh logs and verify the forwarded request
    logs = proxy.get_logs(force=True)
    assert any(f"{ORIGIN_HOST} not found in intercept list" in line for line in logs)

    # Check connections to verify SSL handshakes
    connections = proxy.get_connections()

    # Helper function to check if a connection was intercepted or forwarded
    def find_connection(domain):
        for cid, lines in connections.items():
            if any(domain in line for line in lines):
                return lines
        return None

    # Verify both matching connections were intercepted (client SSL but no server SSL)
    for domain in ["example.com", "example.org"]:
        conn_lines = find_connection(domain)
        assert conn_lines is not None, f"Connection for {domain} not found"
        assert any("[C<>P] SSL handshake completed" in line for line in conn_lines)
        assert not any("[P<>S] SSL handshake completed" in line for line in conn_lines)

    # Verify non-matching connection was forwarded (both client and server SSL)
    nonmatch_lines = find_connection(ORIGIN_HOST)
    assert nonmatch_lines is not None, f"Connection for {ORIGIN_HOST} not found"
    assert any("[C<>P] SSL handshake completed" in line for line in nonmatch_lines)
    assert any("[P<>S] SSL handshake completed" in line for line in nonmatch_lines)


def test_keep_certs(proxy, session, origin):
    """Test that --keep-certs option keeps certificates in current directory."""
    # Start in a clean temp directory
    orig_dir = os.getcwd()
    temp_dir = proxy.tmp_path / "keep_certs_test"
    temp_dir.mkdir()
    os.chdir(temp_dir)

    try:
        # Start proxy with --keep-certs
        proxy.start_proxy("--keep-certs", trust=origin.cert_path)

        # Verify CA cert files exist in current directory
        ca_cert = Path("cert.pem")
        ca_key = Path("key.pem")
        assert ca_cert.exists(), "CA certificate not found"
        assert ca_key.exists(), "CA key not found"

        session.get(f"{origin.base_url}/get")

        # Verify host cert files exist
        host_cert = Path(f"{ORIGIN_HOST}-cert.pem")
        host_key = Path(f"{ORIGIN_HOST}-key.pem")
        assert host_cert.exists(), "Host certificate not found"
        assert host_key.exists(), "Host key not found"

        # Stop proxy and verify files still exist
        proxy.stop_proxy()
        assert ca_cert.exists(), "CA certificate removed"
        assert ca_key.exists(), "CA key removed"
        assert host_cert.exists(), "Host certificate removed"
        assert host_key.exists(), "Host key removed"

    finally:
        # Clean up and restore directory. On Windows the proxy subprocess runs
        # with its cwd inside temp_dir and locks it, so make sure it is stopped
        # (releasing the directory handle) before removing the tree, and retry
        # rmtree to absorb the lag in Windows releasing the handle.
        os.chdir(orig_dir)
        proxy.stop_proxy()
        _robust_rmtree(temp_dir)


def test_proxy_delay(proxy, session):
    """Test that the --delay option enforces connection delays."""
    delay = 0.25
    proxy.start_proxy("--delay", str(delay), "--return-code", str(200))

    # Make a request through the proxy using environment settings
    resp = session.get("https://httpbingo.org/get")
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


def test_concurrent_connections(proxy, origin):
    """Test that the proxy can handle multiple simultaneous connections."""
    proxy.start_proxy(trust=origin.cert_path)

    def make_request(i):
        # Create session with retry strategy
        url = f"{origin.base_url}/get?ndx={i}"
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
                response = session.get("https://httpbingo.org/get", timeout=2.0)
                assert response.status_code == 404, "Expected 404 response"
                print(f"Request test passed with status {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Request resulted in expected exception: {e}")
        finally:
            harness.stop_proxy()

    # Verify we got different ports
    print(f"Ports used: {ports_used}")
    assert len(set(ports_used)) > 1, "Auto-port selection didn't rotate ports"


#
# Upstream mapping (--map) in forward mode
#


def test_forward_map_http_upstream(proxy, session, origin, plain_origin):
    """--map HOST=http://... sends a host's decrypted traffic to a plain-HTTP
    upstream, relaying the request unchanged (Host header included), while
    other hosts in the same run still reach their real destinations."""
    proxy.start_proxy(
        "--map", f"{MAPPED_HOST}=http://127.0.0.1:{plain_origin.port}", trust=origin.cert_path
    )

    resp = session.get(f"https://{MAPPED_HOST}/get?via=map", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data["tls"] is False, "mapped request should reach the plain-HTTP origin"
    assert data["headers"]["Host"] == MAPPED_HOST
    assert data["url"] == "/get?via=map"
    proxy.assert_log_contains(f"Host {MAPPED_HOST} mapped to http://127.0.0.1:{plain_origin.port}")
    proxy.assert_log_contains("[P<>S] Plain TCP connection established")

    # Unmapped passthrough: the TLS origin is reached via its CONNECT target.
    resp = session.get(f"{origin.base_url}/get", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data["tls"] is True, "unmapped request should reach its real (TLS) destination"
    assert data["headers"]["Host"] == f"{ORIGIN_HOST}:{origin.port}"
    proxy.get_logs(force=True)
    proxy.assert_log_contains("[P<>S] SSL handshake completed")
    assert not any(f"Host {ORIGIN_HOST} mapped" in line for line in proxy.get_logs())


def test_forward_map_https_upstream(proxy, session, origin):
    """--map HOST=https://H:P dials H:P over TLS but verifies the upstream
    certificate against the original HOST name."""
    sni_names = _capture_sni(origin)
    proxy.start_proxy(
        "--map", f"{MAPPED_HOST}=https://127.0.0.1:{origin.port}", trust=origin.cert_path
    )

    resp = session.get(f"https://{MAPPED_HOST}/get", timeout=10)
    assert resp.status_code == 200
    assert sni_names == [MAPPED_HOST]
    data = resp.json()
    assert data["tls"] is True
    assert data["headers"]["Host"] == MAPPED_HOST
    proxy.assert_log_contains(f"Host {MAPPED_HOST} mapped to https://127.0.0.1:{origin.port}")
    proxy.assert_log_contains("[P<>S] SSL handshake completed")


def test_forward_map_ip_port_upstream(proxy, session, origin):
    """--map HOST=IP:PORT is TLS to that address and port."""
    sni_names = _capture_sni(origin)
    proxy.start_proxy("--map", f"{MAPPED_HOST}=127.0.0.1:{origin.port}", trust=origin.cert_path)

    resp = session.get(f"https://{MAPPED_HOST}/get", timeout=10)
    assert resp.status_code == 200
    assert sni_names == [MAPPED_HOST]
    assert resp.json()["tls"] is True
    proxy.assert_log_contains(f"Host {MAPPED_HOST} mapped to https://127.0.0.1:{origin.port}")


def test_forward_map_bare_ip_uses_connect_port(proxy, session, origin):
    """In forward mode a bare --map HOST=IP pins the address but keeps the
    port from the CONNECT request."""
    sni_names = _capture_sni(origin)
    proxy.start_proxy("--map", f"{MAPPED_HOST}=127.0.0.1", trust=origin.cert_path)

    resp = session.get(f"https://{MAPPED_HOST}:{origin.port}/get", timeout=10)
    assert resp.status_code == 200
    assert sni_names == [MAPPED_HOST]
    assert resp.json()["tls"] is True
    proxy.assert_log_contains(f"Host {MAPPED_HOST} mapped to https://127.0.0.1:{origin.port}")


def test_forward_map_host_is_case_insensitive(proxy, session, plain_origin):
    """--map host keys match regardless of case; clients send lowercase."""
    proxy.start_proxy("--map", f"{MAPPED_HOST.upper()}=http://127.0.0.1:{plain_origin.port}")

    resp = session.get(f"https://{MAPPED_HOST}/get", timeout=10)
    assert resp.status_code == 200
    assert resp.json()["tls"] is False
    proxy.assert_log_contains(f"Host {MAPPED_HOST} mapped to http://127.0.0.1:{plain_origin.port}")


def test_forward_map_invalid_value():
    result = _run_proxyspy_cli("--map", f"{MAPPED_HOST}=ftp://127.0.0.1", "--", "echo", "hi")
    assert result.returncode == 2
    assert "unsupported scheme" in result.stderr


@pytest.mark.parametrize(
    "value, default_port, expected",
    [
        ("10.0.0.1", 443, ("https", "10.0.0.1", 443)),
        ("10.0.0.1", None, ("https", "10.0.0.1", None)),
        ("backend.example", 8443, ("https", "backend.example", 8443)),
        ("10.0.0.1:8443", None, ("https", "10.0.0.1", 8443)),
        ("https://10.0.0.1", None, ("https", "10.0.0.1", 443)),
        ("https://10.0.0.1:8443", 443, ("https", "10.0.0.1", 8443)),
        ("HTTPS://Backend.Example/", None, ("https", "backend.example", 443)),
        ("http://127.0.0.1", 443, ("http", "127.0.0.1", 80)),
        ("http://127.0.0.1:8787", None, ("http", "127.0.0.1", 8787)),
        # IPv6 literals are out of scope, but must not be misparsed as IP:PORT
        ("::1", 443, ("https", "::1", 443)),
    ],
)
def test_parse_upstream(value, default_port, expected):
    upstream = proxyspy.parse_upstream(value, default_port)
    assert tuple(upstream[:3]) == expected
    assert upstream.addresses is None  # only resolved later, in reverse mode


@pytest.mark.parametrize(
    "value",
    [
        "ftp://10.0.0.1",
        "http://",
        "http://127.0.0.1:notaport",
        "http://127.0.0.1:0",
        "http://127.0.0.1:8787/path",
        "http://127.0.0.1:8787?q=1",
        "http://user:pw@127.0.0.1",
        "10.0.0.1:notaport",
        "10.0.0.1:70000",
        ":8443",
    ],
)
def test_parse_upstream_rejects(value):
    with pytest.raises(ValueError):
        proxyspy.parse_upstream(value, 443)


#
# Request header injection (--add-header)
#


def _header_values(data, name):
    """All values of header name (case-insensitive) from an origin echo."""
    return [v for k, v in data["header_list"] if k.lower() == name.lower()]


def _start_add_header_proxy(proxy, origin_port, *headers, trust=None):
    args = ["--map", f"{MAPPED_HOST}=http://127.0.0.1:{origin_port}"]
    for header in headers:
        args += ["--add-header", header]
    proxy.start_proxy(*args, trust=trust)


def test_add_header_replaces_existing(proxy, keepalive_origin):
    """--add-header sets the header: a client-sent header of the same name
    (any case) is replaced, not duplicated, and the rewritten head is logged."""
    _start_add_header_proxy(
        proxy, keepalive_origin.port, "X-Test: 1", "CF-Connecting-IP: 203.0.113.7"
    )

    with requests.Session() as s:
        resp = s.get(f"https://{MAPPED_HOST}/get", headers={"x-test": "client"}, timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert _header_values(data, "X-Test") == ["1"]
    assert _header_values(data, "CF-Connecting-IP") == ["203.0.113.7"]
    assert data["headers"]["Host"] == MAPPED_HOST
    proxy.assert_log_contains("| X-Test: 1")
    proxy.assert_log_contains("| CF-Connecting-IP: 203.0.113.7")
    assert not any("x-test: client" in line for line in proxy.get_logs())


def test_add_header_every_request_on_keepalive(proxy, keepalive_origin):
    """Every request on a reused (keep-alive) connection carries the header,
    not just the first."""
    _start_add_header_proxy(proxy, keepalive_origin.port, "X-Test: 1")

    with requests.Session() as s:
        results = [
            s.get(f"https://{MAPPED_HOST}/get?n={i}", headers={"X-Test": "client"}, timeout=10)
            for i in range(3)
        ]
    datas = [r.json() for r in results]
    for data in datas:
        assert _header_values(data, "X-Test") == ["1"], data["url"]
    # All three went over one upstream connection, so reuse really happened.
    assert len({d["peer_port"] for d in datas}) == 1
    logs = proxy.get_logs(force=True)
    assert sum(f"CONNECT {MAPPED_HOST}:443" in line for line in logs) == 1


def test_add_header_frames_request_bodies(proxy, keepalive_origin):
    """A Content-Length body is forwarded intact (even if it looks like a
    request head) and the following request on the connection still gets the
    header."""
    _start_add_header_proxy(proxy, keepalive_origin.port, "X-Test: 1")
    # Large enough to span several reads, and containing a decoy request head
    # that a naive "find the next CRLFCRLF" rewriter would mangle.
    decoy = b"\r\n\r\nGET /decoy HTTP/1.1\r\nX-Test: decoy\r\n\r\n"
    body = b"a" * 150_000 + decoy + b"b" * 1000

    with requests.Session() as s:
        posted = s.post(f"https://{MAPPED_HOST}/post", data=body, timeout=10).json()
        after = s.get(f"https://{MAPPED_HOST}/get", timeout=10).json()

    assert posted["body_length"] == len(body)
    assert _header_values(posted, "X-Test") == ["1"]
    assert _header_values(after, "X-Test") == ["1"]
    assert after["url"] == "/get"
    assert posted["peer_port"] == after["peer_port"]


def test_add_header_skips_unmapped_hosts(proxy, session, origin, keepalive_origin):
    """Hosts without a --map entry receive no injected header."""
    _start_add_header_proxy(proxy, keepalive_origin.port, "X-Test: 1", trust=origin.cert_path)

    data = session.get(f"{origin.base_url}/get", timeout=10).json()
    assert data["tls"] is True
    assert _header_values(data, "X-Test") == []

    with requests.Session() as s:
        mapped = s.get(f"https://{MAPPED_HOST}/get", timeout=10).json()
    assert _header_values(mapped, "X-Test") == ["1"]


def test_add_header_invalid_format():
    result = _run_proxyspy_cli("--add-header", "NoColonHere", "--", "echo", "hi")
    assert result.returncode == 2
    assert "--add-header expects" in result.stderr


def test_add_header_rejects_framing_header():
    result = _run_proxyspy_cli("--add-header", "Content-Length: 5", "--", "echo", "hi")
    assert result.returncode == 2
    assert "message framing" in result.stderr


def _run_framer(chunks, headers=(("X-Test", "1"),)):
    """Feed chunks through a RequestFramer; return (output bytes, heads, warnings)."""
    framer = proxyspy.RequestFramer(list(headers))
    out, heads, warnings = b"", [], []
    for chunk in chunks:
        for kind, payload in framer.feed(chunk):
            if kind == "warn":
                warnings.append(payload)
            else:
                out += payload
                if kind == "head":
                    heads.append(payload)
    return out, heads, warnings


def test_request_framer_sets_header_preserving_order():
    req = b"GET / HTTP/1.1\r\nHost: h\r\nx-test: old\r\nAccept: */*\r\n\r\n"
    out, heads, warnings = _run_framer([req])
    assert out == b"GET / HTTP/1.1\r\nHost: h\r\nAccept: */*\r\nX-Test: 1\r\n\r\n"
    assert len(heads) == 1 and not warnings


def test_request_framer_head_split_across_reads():
    req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    whole, _, _ = _run_framer([req])
    bytewise, heads, warnings = _run_framer([bytes([c]) for c in req])
    assert bytewise == whole == b"GET / HTTP/1.1\r\nHost: h\r\nX-Test: 1\r\n\r\n"
    assert len(heads) == 1 and not warnings


def test_request_framer_pipelined_with_bodies():
    body = b"x\r\n\r\nGET /no HTTP/1.1\r\n\r\n"
    req1 = b"POST /a HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    req2 = b"GET /b HTTP/1.1\r\nX-TEST: dup\r\n\r\n"
    out, heads, warnings = _run_framer([req1 + req2])
    assert out == (
        b"POST /a HTTP/1.1\r\nContent-Length: %d\r\nX-Test: 1\r\n\r\n" % len(body)
        + body
        + b"GET /b HTTP/1.1\r\nX-Test: 1\r\n\r\n"
    )
    assert len(heads) == 2 and not warnings


def test_request_framer_chunked_falls_back_to_passthrough():
    req1 = b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    req2 = b"GET /b HTTP/1.1\r\n\r\n"
    out, heads, warnings = _run_framer([req1, req2])
    # The chunked request's own head is still rewritten; everything after it,
    # including the next request, passes through unmodified.
    assert out == (
        b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-Test: 1\r\n\r\n"
        b"3\r\nabc\r\n0\r\n\r\n" + req2
    )
    assert len(heads) == 1
    assert len(warnings) == 1 and "Transfer-Encoding: chunked" in warnings[0]


@pytest.mark.parametrize(
    "head",
    [
        b"NOT A REQUEST\r\n\r\n",
        b"GET / HTTP/2\r\n\r\n",
        b"GET / HTTP/1.1\r\nno-colon\r\n\r\n",
        b"GET / HTTP/1.1\r\nA: b\r\n folded\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
    ],
)
def test_request_framer_unparseable_passthrough(head):
    trailer = b"GET /next HTTP/1.1\r\n\r\n"
    out, heads, warnings = _run_framer([head + trailer])
    assert out == head + trailer
    assert heads == []
    assert len(warnings) == 1 and "unparseable" in warnings[0]


def test_request_framer_oversized_head_passthrough():
    junk = b"A" * (proxyspy.MAX_REQUEST_HEAD + 1)
    out, heads, warnings = _run_framer([junk, b"more"])
    assert out == junk + b"more"
    assert heads == [] and len(warnings) == 1


def test_request_framer_upgrade_passthrough():
    req = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    out, heads, warnings = _run_framer([req, b"\x81\x05hello"])
    assert out == req[:-2] + b"X-Test: 1\r\n\r\n" + b"\x81\x05hello"
    assert len(heads) == 1 and len(warnings) == 1


#
# Reverse / transparent mode
#


class ReverseHarness:
    """Lifecycle manager for a standalone (--reverse) proxyspy instance.

    Unlike ProxyTestHarness, reverse mode has no child command and uses a
    persistent --cert-dir, so this launches proxyspy directly and parses the
    auto-selected listen port from the log.
    """

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.cert_dir = tmp_path / "certs"
        self.log_file = tmp_path / "reverse.log"
        self.script_path = find_proxyspy()
        self.process = None
        self.port = None

    def start(self, *extra_args, expect_exit=False, trust=None):
        if isinstance(self.script_path, Path) or str(self.script_path).endswith(".py"):
            cmd = ["python", str(self.script_path)]
        else:
            cmd = [str(self.script_path)]
        cmd += [
            "--reverse",
            "--port",
            "0",
            "--cert-dir",
            str(self.cert_dir),
            "--logfile",
            str(self.log_file),
            "--debug",
        ]
        cmd += list(extra_args)
        print(f"\nStarting reverse proxy: {' '.join(cmd)}")
        # proxyspy opens the logfile in append mode, so a second start() on the
        # same tmp_path would see the previous run's "listening" line and return
        # early (before this run self-heals/logs). Truncate so we only ever match
        # this invocation's output.
        if self.log_file.exists():
            self.log_file.unlink()
        env = os.environ.copy()
        if trust:
            # Trust the in-process origin's cert for upstream verification.
            env["SSL_CERT_FILE"] = str(trust)
        self.process = Popen(cmd, env=env)

        # When we expect a clean startup, wait for the listening line and port.
        if expect_exit:
            self.process.wait(timeout=10)
            return
        start_time = time.time()
        while time.time() - start_time < 10:
            if self.process.poll() is not None:
                raise RuntimeError("Reverse proxy exited during startup")
            if self.log_file.exists():
                for line in self.log_file.read_text().splitlines():
                    if "Reverse proxy listening on 127.0.0.1:" in line:
                        self.port = int(line.rsplit(":", 1)[1])
                        return
            time.sleep(0.1)
        raise RuntimeError("Reverse proxy failed to start within 10 seconds")

    @property
    def ca_path(self):
        return str(self.cert_dir / "cert.pem")

    def connect(self, host, verify=True):
        """Open a TLS connection to the proxy with the given SNI host."""
        if verify:
            ctx = ssl.create_default_context(cafile=self.ca_path)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        return ctx.wrap_socket(raw, server_hostname=host)

    def logs(self):
        return self.log_file.read_text() if self.log_file.exists() else ""

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
                self.process.wait()


@pytest.fixture
def reverse(tmp_path):
    harness = ReverseHarness(tmp_path)
    try:
        yield harness
    finally:
        harness.stop()


def test_reverse_intercept(reverse):
    """Reverse mode returns canned responses, selecting the cert via SNI,
    without ever contacting a real upstream."""
    reverse.start(
        "--intercept-host",
        "example.com",
        "--return-code",
        "418",
        "--return-header",
        "X-Test: reverse",
        "--return-data",
        "teapot",
    )

    sock = reverse.connect("example.com")
    sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    sock.close()

    text = response.decode("iso-8859-1")
    assert "418 Intercepted" in text
    assert "X-Test: reverse" in text
    assert text.endswith("teapot")

    logs = reverse.logs()
    # Cert chosen via SNI, request intercepted, no upstream handshake.
    assert "SSL handshake completed (SNI: example.com)" in logs
    assert "example.com found in intercept list" in logs
    assert "[P<>S] SSL handshake completed" not in logs


def test_reverse_forward(reverse, origin):
    """Reverse mode forwards to the upstream, MITMing both ends. The upstream
    is pinned to the in-process origin with --map, which also exercises the
    upstream-override path and avoids any public-network dependency."""
    sni_names = _capture_sni(origin)
    reverse.start(
        "--prepare-host",
        ORIGIN_HOST,
        "--map",
        f"{ORIGIN_HOST}=127.0.0.1",
        "--upstream-port",
        str(origin.port),
        trust=origin.cert_path,
    )

    logs = reverse.logs()
    assert f"Upstream for {ORIGIN_HOST} ->" in logs, "Upstream was not configured at startup"

    sock = reverse.connect(ORIGIN_HOST)
    sock.sendall(f"GET /get HTTP/1.1\r\nHost: {ORIGIN_HOST}\r\nConnection: close\r\n\r\n".encode())
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    sock.close()

    status_line = response.split(b"\r\n", 1)[0]
    assert status_line.startswith(b"HTTP/") and b" 200" in status_line, status_line
    logs = reverse.logs()
    assert f"SSL handshake completed (SNI: {ORIGIN_HOST})" in logs
    assert "[P<>S] SSL handshake completed" in logs
    # The upstream is dialed by IP but verified against the original name.
    assert sni_names == [ORIGIN_HOST]


def test_reverse_loopback_guard(reverse):
    """A host already resolving to loopback must abort startup with a clear
    error rather than forwarding into the proxy itself."""
    reverse.start("--prepare-host", "localhost", expect_exit=True)

    assert reverse.process.returncode == 1
    assert "loopback address" in reverse.logs()


def _read_all(sock):
    """Read from sock until the peer closes it."""
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return response
        response += chunk


def test_reverse_map_http_upstream(reverse, plain_origin):
    """Reverse mode honors an explicit http:// --map (no upstream TLS), even
    to loopback. The --map entry alone is enough: a mapped host counts as
    declared, without --prepare-host or --intercept-host."""
    reverse.start("--map", f"{MAPPED_HOST}=http://127.0.0.1:{plain_origin.port}")
    logs = reverse.logs()
    assert f"Upstream for {MAPPED_HOST} -> http://127.0.0.1:{plain_origin.port}" in logs
    # A mapped host counts as declared: cert pre-generated, redirect listed.
    assert f"Requested certificate for {MAPPED_HOST}" in logs
    assert f"Redirect these hosts to 127.0.0.1 in /etc/hosts: {MAPPED_HOST}" in logs

    sock = reverse.connect(MAPPED_HOST)
    sock.sendall(f"GET /get HTTP/1.1\r\nHost: {MAPPED_HOST}\r\nConnection: close\r\n\r\n".encode())
    response = _read_all(sock)
    sock.close()

    head, _, body = response.partition(b"\r\n\r\n")
    assert b" 200 " in head.split(b"\r\n", 1)[0], head
    data = json.loads(body)
    assert data["tls"] is False
    assert data["headers"]["Host"] == MAPPED_HOST
    assert "[P<>S] Plain TCP connection established" in reverse.logs()


def test_reverse_map_name_resolved_at_startup(reverse, origin):
    """A --map target given as a name is resolved at startup, before any
    /etc/hosts redirect could send it back to us, and still verified against
    the original host name."""
    sni_names = _capture_sni(origin)
    reverse.start("--map", f"{MAPPED_HOST}=https://localhost:{origin.port}", trust=origin.cert_path)
    logs = reverse.logs()
    assert f"Upstream for {MAPPED_HOST} -> https://localhost:{origin.port} (" in logs

    sock = reverse.connect(MAPPED_HOST)
    sock.sendall(f"GET /get HTTP/1.1\r\nHost: {MAPPED_HOST}\r\nConnection: close\r\n\r\n".encode())
    response = _read_all(sock)
    sock.close()

    head, _, body = response.partition(b"\r\n\r\n")
    assert b" 200 " in head.split(b"\r\n", 1)[0], head
    assert json.loads(body)["tls"] is True
    assert sni_names == [MAPPED_HOST]


def test_reverse_map_refuses_self_loop(reverse):
    """A mapping that would dial the proxy's own listen address is refused at
    startup instead of looping. The listen port is chosen explicitly (the
    harness's --port 0 is overridden, since argparse keeps the last value)
    and the bare-IP map inherits it via --upstream-port, just as the default
    --upstream-port 443 would against a proxy listening on 443."""
    port = str(proxyspy.find_free_port())
    reverse.start(
        "--port",
        port,
        "--upstream-port",
        port,
        "--map",
        f"{MAPPED_HOST}=127.0.0.1",
        expect_exit=True,
    )
    assert reverse.process.returncode == 1
    assert "would connect back to this proxy" in reverse.logs()


def _fake_getaddrinfo(answers):
    """getaddrinfo stand-in returning answers[name] (a list of IPs)."""

    def getaddrinfo(name, port, *args, **kwargs):
        if name not in answers:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (ip, port),
            )
            for ip in answers[name]
        ]

    return getaddrinfo


def test_resolve_upstream_pins_mapped_name(monkeypatch):
    """A mapped name is resolved once, to all of its addresses; a later DNS
    change (e.g. the /etc/hosts redirect) does not affect where we dial."""
    answers = {"api.example": ["203.0.113.5", "2001:db8::5", "203.0.113.5"]}
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(answers))
    overrides = {"api.example": proxyspy.parse_upstream("https://api.example:8443", 443)}

    upstream = proxyspy.resolve_upstream("API.example", 443, overrides, listen=("127.0.0.1", 443))
    assert upstream == ("https", "api.example", 8443, ("203.0.113.5", "2001:db8::5"))
    assert "(203.0.113.5, 2001:db8::5)" in proxyspy.format_upstream(upstream)

    answers["api.example"] = ["127.0.0.1"]  # now redirected to us
    dialed = []

    def fake_create_connection(address, *args, **kwargs):
        dialed.append(address)
        return object()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    proxyspy.connect_upstream(upstream)
    assert dialed == [("203.0.113.5", 8443)]


def test_resolve_upstream_mapped_port_defaults(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"10.0.0.1": ["10.0.0.1"]}))
    overrides = {"h": proxyspy.parse_upstream("10.0.0.1", None)}
    assert proxyspy.resolve_upstream("h", 8443, overrides) == (
        "https",
        "10.0.0.1",
        8443,
        ("10.0.0.1",),
    )


def test_resolve_upstream_unmapped_pins_addresses(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"real.example": ["198.51.100.7"]})
    )
    upstream = proxyspy.resolve_upstream("real.example", 443, {})
    assert upstream == ("https", "real.example", 443, ("198.51.100.7",))


def test_resolve_upstream_unmapped_loopback_refused(monkeypatch):
    """Any loopback answer for an unmapped host means it is redirected to us."""
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"real.example": ["198.51.100.7", "127.0.0.1"]})
    )
    with pytest.raises(RuntimeError, match="loopback address"):
        proxyspy.resolve_upstream("real.example", 443, {})


@pytest.mark.parametrize(
    "value, answers, refused",
    [
        # Literal loopback on our own listen port: refused.
        ("127.0.0.1", {"127.0.0.1": ["127.0.0.1"]}, True),
        # A name that already resolves to us (e.g. a manual /etc/hosts edit).
        ("https://redirected.example", {"redirected.example": ["127.0.0.1"]}, True),
        # A local dev server on another port is an intentional loopback map.
        ("http://localhost:8787", {"localhost": ["::1", "127.0.0.1"]}, False),
        # We listen on 127.0.0.1 only, so ::1 on our port is not us.
        ("https://[::1]", {"::1": ["::1"]}, False),
    ],
)
def test_resolve_upstream_self_loop_guard(monkeypatch, value, answers, refused):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(answers))
    overrides = {"h": proxyspy.parse_upstream(value, 443)}
    if refused:
        with pytest.raises(RuntimeError, match="connect back to this proxy"):
            proxyspy.resolve_upstream("h", 443, overrides, listen=("127.0.0.1", 443))
    else:
        proxyspy.resolve_upstream("h", 443, overrides, listen=("127.0.0.1", 443))


def test_connect_upstream_falls_back_to_next_address():
    """Pre-resolved addresses are tried in order, so a server listening on
    only one of them (e.g. IPv4 127.0.0.1 when localhost is ::1 first) is
    still reached, as socket.create_connection() would for a name."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        upstream = proxyspy.Upstream("http", "localhost", port, ("::1", "127.0.0.1"))
        with proxyspy.connect_upstream(upstream) as conn:
            assert conn.getpeername()[:2] == ("127.0.0.1", port)


def test_connect_upstream_raises_when_all_fail():
    port = proxyspy.find_free_port()
    with pytest.raises(OSError):
        proxyspy.connect_upstream(proxyspy.Upstream("http", "x", port, ("127.0.0.1",)))


def test_reverse_add_header_keepalive(reverse, keepalive_origin):
    """--add-header works in reverse mode too, on every request of a
    keep-alive connection."""
    reverse.start(
        "--map",
        f"{MAPPED_HOST}=http://127.0.0.1:{keepalive_origin.port}",
        "--add-header",
        "X-Test: 1",
    )

    sock = reverse.connect(MAPPED_HOST)
    req = "GET /get?n=%d HTTP/1.1\r\nHost: " + MAPPED_HOST + "\r\nX-Test: client\r\n%s\r\n"
    # Pipeline two requests on one connection; the second asks the origin to
    # close afterwards so we can read to EOF.
    sock.sendall((req % (1, "") + req % (2, "Connection: close\r\n")).encode())
    response = _read_all(sock)
    sock.close()

    bodies = []
    while response:
        head, _, rest = response.partition(b"\r\n\r\n")
        length = int(re.search(rb"(?i)\r\ncontent-length: *(\d+)", head).group(1))
        bodies.append(json.loads(rest[:length]))
        response = rest[length:]
    assert [b["url"] for b in bodies] == ["/get?n=1", "/get?n=2"]
    for body in bodies:
        assert _header_values(body, "X-Test") == ["1"]
    assert bodies[0]["peer_port"] == bodies[1]["peer_port"]


#
# Persistent cert-dir ownership under sudo
#


@pytest.mark.skipif(os.name != "posix", reason="pwd/sudo are POSIX-only")
def test_default_cert_dir_uses_sudo_user_home(monkeypatch):
    """Under sudo the persistent dir must resolve to the invoking user's home,
    not root's, so the CA lands where the user can trust it."""
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setenv("SUDO_USER", "someuser")

    class _PW:
        pw_dir = "/home/someuser"
        pw_uid = 1000
        pw_gid = 1000
        pw_name = "someuser"

    import pwd

    monkeypatch.setattr(pwd, "getpwnam", lambda name: _PW if name == "someuser" else 1 / 0)
    assert proxyspy.default_cert_dir() == os.path.join("/home/someuser", ".proxyspy")


def test_sudo_pw_none_without_sudo(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert proxyspy._sudo_pw() is None


@pytest.mark.skipif(os.name != "posix", reason="os.chown is POSIX-only")
def test_chown_to_sudo_user_noop_when_not_sudo(monkeypatch, tmp_path):
    """Without SUDO_USER the chown helper must do nothing (and never touch the
    filesystem), so ordinary non-sudo runs are unaffected."""
    monkeypatch.delenv("SUDO_USER", raising=False)
    called = []
    monkeypatch.setattr(os, "chown", lambda *a, **k: called.append(a))
    (tmp_path / "cert.pem").write_text("x")

    proxyspy._chown_to_sudo_user(str(tmp_path))
    assert called == []


#
# Standalone forward mode (--standalone)
#


class StandaloneHarness:
    """Lifecycle manager for a standalone (--standalone) proxyspy instance.

    Like reverse mode it has no child command and uses a persistent --cert-dir,
    so this launches proxyspy directly and parses the auto-selected port from
    the log. The banner is captured from stdout.
    """

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.cert_dir = tmp_path / "certs"
        self.log_file = tmp_path / "standalone.log"
        self.script_path = find_proxyspy()
        self.process = None
        self.port = None
        self.stdout = ""

    def start(self, *extra_args, trust=None):
        if isinstance(self.script_path, Path) or str(self.script_path).endswith(".py"):
            cmd = ["python", str(self.script_path)]
        else:
            cmd = [str(self.script_path)]
        cmd += [
            "--standalone",
            "--port",
            "0",
            "--cert-dir",
            str(self.cert_dir),
            "--logfile",
            str(self.log_file),
            "--debug",
        ]
        cmd += list(extra_args)
        print(f"\nStarting standalone proxy: {' '.join(cmd)}")
        env = os.environ.copy()
        if trust:
            env["SSL_CERT_FILE"] = str(trust)
        self.process = Popen(cmd, env=env, stdout=subprocess.PIPE, text=True)

        # The banner is printed after the server starts; parse the log for the
        # port so we don't block on the pipe.
        start_time = time.time()
        while time.time() - start_time < 10:
            if self.process.poll() is not None:
                raise RuntimeError("Standalone proxy exited during startup")
            if self.log_file.exists():
                for line in self.log_file.read_text().splitlines():
                    if "Proxy server started on port" in line:
                        self.port = int(line.split("port")[1].strip())
                        return
            time.sleep(0.1)
        raise RuntimeError("Standalone proxy failed to start within 10 seconds")

    @property
    def ca_path(self):
        return str(self.cert_dir / "cert.pem")

    @property
    def env_file(self):
        return self.cert_dir / "env"

    def proxy_url(self):
        return f"http://localhost:{self.port}"

    def logs(self):
        return self.log_file.read_text() if self.log_file.exists() else ""

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                out, _ = self.process.communicate(timeout=5)
            except Exception:
                self.process.kill()
                out, _ = self.process.communicate()
            self.stdout = out or ""


@pytest.fixture
def standalone(tmp_path):
    harness = StandaloneHarness(tmp_path)
    try:
        yield harness
    finally:
        harness.stop()


def test_standalone_rejects_reverse():
    result = _run_proxyspy_cli("--standalone", "--reverse")
    assert result.returncode == 2
    assert "mutually exclusive" in result.stderr


def test_standalone_rejects_command():
    result = _run_proxyspy_cli("--standalone", "--", "echo", "hi")
    assert result.returncode == 2
    assert "cannot be given in --reverse or --standalone" in result.stderr


def test_standalone_writes_env_file_and_banner(standalone):
    """Standalone mode writes a source-able env file and prints a copy-pasteable
    banner, then removes the env file on clean shutdown."""
    standalone.start()

    env_file = standalone.env_file
    assert env_file.exists(), "env file should exist while running"
    contents = env_file.read_text()
    proxy_url = standalone.proxy_url()
    # Values are shell-quoted (shlex.quote), which matters on Windows where the
    # cert path contains backslashes and gets wrapped in single quotes.
    ca = shlex.quote(standalone.ca_path)
    assert f"export HTTPS_PROXY={shlex.quote(proxy_url)}" in contents
    assert f"export SSL_CERT_FILE={ca}" in contents
    assert f"export CONDA_SSL_VERIFY={ca}" in contents
    # Empty NO_PROXY must be shell-quoted so `source` doesn't choke.
    assert "export NO_PROXY=''" in contents

    standalone.stop()
    # On POSIX, stop() sends SIGTERM which proxyspy converts to a clean shutdown
    # that removes the env file. On Windows, terminate() maps to TerminateProcess
    # (an uncatchable hard kill), so the file may persist until the next run; we
    # don't assert removal there.
    if os.name == "posix":
        assert not env_file.exists(), "env file should be removed on shutdown"

    # The banner went to stdout with the same values, ready to copy-paste.
    banner = standalone.stdout
    assert "ProxySpy standalone (forward proxy) listening" in banner
    assert f"export HTTPS_PROXY={shlex.quote(proxy_url)}" in banner
    assert f"source {shlex.quote(str(env_file))}" in banner


def test_standalone_banner_survives_unwritable_env_file(standalone):
    """If the env file cannot be written (e.g. a root-owned ~/.proxyspy from a
    prior sudo run), the copy-pasteable banner must still print; only the
    'source ...' line is dropped."""
    # Pre-create <cert-dir>/env as a directory so open(path, "w") fails with an
    # OSError, without needing to fiddle with ownership or permissions.
    standalone.cert_dir.mkdir(parents=True, exist_ok=True)
    (standalone.cert_dir / "env").mkdir()

    standalone.start()
    proxy_url = standalone.proxy_url()
    standalone.stop()

    assert "Cannot write env file" in standalone.logs()
    banner = standalone.stdout
    assert "ProxySpy standalone (forward proxy) listening" in banner
    assert f"export HTTPS_PROXY={shlex.quote(proxy_url)}" in banner
    # No source-able file, so that line is omitted rather than pointing nowhere.
    assert "source " not in banner


def test_standalone_forwards_request(standalone, origin):
    """A client that sources the printed env vars actually routes HTTPS through
    the standalone proxy to the upstream origin."""
    standalone.start(trust=origin.cert_path)

    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": standalone.proxy_url(), "https": standalone.proxy_url()}
    session.verify = standalone.ca_path
    resp = session.get(f"https://{ORIGIN_HOST}:{origin.port}/get", timeout=10)

    assert resp.status_code == 200
    assert resp.json()["url"] == "/get"
    logs = standalone.logs()
    assert f"CONNECT {ORIGIN_HOST}:{origin.port}" in logs
    assert "[P<>S] SSL handshake completed" in logs


#
# /etc/hosts management (--manage-hosts / --restore-hosts)
#


def _fenced(host, pid):
    """Build a PID-tagged managed block, matching proxyspy._fenced_block."""
    return (
        "# >>> proxyspy %d >>>\n"
        "# Managed by proxyspy (PID %d). Do not edit by hand.\n"
        "127.0.0.1 %s\n"
        "# <<< proxyspy %d <<<\n" % (pid, pid, host, pid)
    )


@pytest.fixture
def pids(monkeypatch):
    """(live, dead) foreign PIDs with _pid_alive mocked to match.

    The block-ownership tests never probe real processes: on Windows
    os.kill(pid, 0) sends CTRL_C_EVENT and, on Python 3.10, can fall through
    to TerminateProcess. The real liveness check is covered by the POSIX-only
    test_pid_alive. Our own PID is reported alive, as it is in reality."""
    mine = os.getpid()
    live, dead = mine + 1, mine + 2
    monkeypatch.setattr(proxyspy, "_pid_alive", lambda pid: pid in (mine, live))
    return live, dead


def _dead_pid():
    """A PID that is no longer running: a child we spawned and reaped. Only
    for the POSIX-only test_pid_alive; see the pids fixture."""
    proc = subprocess.Popen([sys.executable, "-c", ""])
    proc.wait()
    return proc.pid


def test_strip_managed_block_absent():
    text = "127.0.0.1 localhost\n::1 localhost\n"
    assert proxyspy._strip_managed_block(text) == text


def test_strip_managed_block_present():
    text = (
        "127.0.0.1 localhost\n"
        "# >>> proxyspy >>>\n"
        "# Managed by proxyspy (PID 123). Do not edit by hand.\n"
        "127.0.0.1 example.com\n"
        "# <<< proxyspy <<<\n"
        "::1 localhost\n"
    )
    assert proxyspy._strip_managed_block(text) == "127.0.0.1 localhost\n::1 localhost\n"


def test_strip_managed_block_at_start():
    text = "# >>> proxyspy >>>\n127.0.0.1 example.com\n# <<< proxyspy <<<\n::1 localhost\n"
    assert proxyspy._strip_managed_block(text) == "::1 localhost\n"


def test_strip_managed_block_at_end():
    text = "127.0.0.1 localhost\n# >>> proxyspy >>>\n127.0.0.1 example.com\n# <<< proxyspy <<<\n"
    assert proxyspy._strip_managed_block(text) == "127.0.0.1 localhost\n"


def test_strip_managed_block_no_trailing_newline():
    text = "127.0.0.1 localhost\n# >>> proxyspy >>>\n127.0.0.1 example.com\n# <<< proxyspy <<<"
    assert proxyspy._strip_managed_block(text) == "127.0.0.1 localhost\n"


def test_strip_managed_block_two_blocks():
    text = (
        "# >>> proxyspy >>>\n127.0.0.1 a.com\n# <<< proxyspy <<<\n"
        "127.0.0.1 localhost\n"
        "# >>> proxyspy >>>\n127.0.0.1 b.com\n# <<< proxyspy <<<\n"
    )
    assert proxyspy._strip_managed_block(text) == "127.0.0.1 localhost\n"


def test_strip_managed_block_unterminated_begin():
    """A hand-corrupted file with a begin marker but no matching end marker
    is left untouched rather than swallowing the rest of the file."""
    text = "127.0.0.1 localhost\n# >>> proxyspy >>>\n127.0.0.1 example.com\n"
    assert proxyspy._strip_managed_block(text) == text


def test_strip_managed_block_pid_tagged():
    text = (
        "127.0.0.1 localhost\n"
        "# >>> proxyspy 4242 >>>\n"
        "# Managed by proxyspy (PID 4242). Do not edit by hand.\n"
        "127.0.0.1 example.com\n"
        "# <<< proxyspy 4242 <<<\n"
        "::1 localhost\n"
    )
    assert proxyspy._strip_managed_block(text) == "127.0.0.1 localhost\n::1 localhost\n"


def test_strip_managed_block_keeps_live_foreign_block(pids):
    """_keep_live_foreign_block keeps a block owned by another live process
    while still removing this process's own block."""
    foreign, _ = pids
    mine = os.getpid()
    text = _fenced("a.example.com", foreign) + _fenced("b.example.com", mine)
    stripped = proxyspy._strip_managed_block(text, keep=proxyspy._keep_live_foreign_block)
    assert "127.0.0.1 a.example.com" in stripped
    assert "b.example.com" not in stripped


def test_strip_managed_block_drops_dead_block(pids):
    _, dead = pids
    text = _fenced("a.example.com", dead)
    stripped = proxyspy._strip_managed_block(text, keep=proxyspy._keep_live_foreign_block)
    assert stripped == ""


def test_write_managed_hosts_appends_block(tmp_path):
    hosts_path = tmp_path / "hosts"
    bak_path = tmp_path / "hosts.bak"
    hosts_path.write_text("127.0.0.1 localhost\n")

    proxyspy.write_managed_hosts(
        ["example.com", "example.org"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )

    text = hosts_path.read_text()
    assert text.startswith("127.0.0.1 localhost\n")
    assert "# >>> proxyspy %d >>>" % os.getpid() in text
    assert "# <<< proxyspy %d <<<" % os.getpid() in text
    assert "127.0.0.1 example.com" in text
    assert "127.0.0.1 example.org" in text
    # Hosts are sorted within the block
    assert text.index("example.com") < text.index("example.org")


def test_write_managed_hosts_idempotent_across_restarts(tmp_path):
    hosts_path = tmp_path / "hosts"
    bak_path = tmp_path / "hosts.bak"
    hosts_path.write_text("127.0.0.1 localhost\n")

    proxyspy.write_managed_hosts(
        ["example.com"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )
    proxyspy.write_managed_hosts(
        ["example.org"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )

    text = hosts_path.read_text()
    assert text.count("# >>> proxyspy %d >>>" % os.getpid()) == 1
    assert "example.com" not in text
    assert "127.0.0.1 example.org" in text
    assert text.startswith("127.0.0.1 localhost\n")


def test_write_managed_hosts_backs_up_once(tmp_path):
    hosts_path = tmp_path / "hosts"
    bak_path = tmp_path / "hosts.bak"
    original = "127.0.0.1 localhost\n"
    hosts_path.write_text(original)

    proxyspy.write_managed_hosts(
        ["example.com"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )
    assert bak_path.read_text() == original

    proxyspy.write_managed_hosts(
        ["example.org"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )
    assert bak_path.read_text() == original


def test_remove_managed_hosts_restores_original(tmp_path):
    hosts_path = tmp_path / "hosts"
    bak_path = tmp_path / "hosts.bak"
    original = "127.0.0.1 localhost\n::1 localhost\n"
    hosts_path.write_text(original)

    proxyspy.write_managed_hosts(
        ["example.com"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )
    assert proxyspy.remove_managed_hosts(hosts_path=str(hosts_path)) is True
    assert hosts_path.read_text() == original


def test_remove_managed_hosts_noop_when_absent(tmp_path):
    hosts_path = tmp_path / "hosts"
    original = "127.0.0.1 localhost\n"
    hosts_path.write_text(original)

    assert proxyspy.remove_managed_hosts(hosts_path=str(hosts_path)) is False
    assert hosts_path.read_text() == original


def test_write_managed_hosts_preserves_live_foreign_block(tmp_path, pids):
    """A concurrent live session's block must survive our write, so we do not
    silently stop intercepting for that session."""
    hosts_path = tmp_path / "hosts"
    bak_path = tmp_path / "hosts.bak"
    foreign, _ = pids
    hosts_path.write_text("127.0.0.1 localhost\n" + _fenced("a.example.com", foreign))

    proxyspy.write_managed_hosts(
        ["b.example.com"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )

    text = hosts_path.read_text()
    assert "127.0.0.1 a.example.com" in text
    assert "127.0.0.1 b.example.com" in text
    assert text.count("# >>> proxyspy") == 2


def test_write_managed_hosts_drops_dead_block(tmp_path, pids):
    _, dead = pids
    hosts_path = tmp_path / "hosts"
    bak_path = tmp_path / "hosts.bak"
    hosts_path.write_text("127.0.0.1 localhost\n" + _fenced("a.example.com", dead))

    proxyspy.write_managed_hosts(
        ["b.example.com"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )

    text = hosts_path.read_text()
    assert "a.example.com" not in text
    assert "127.0.0.1 b.example.com" in text
    assert text.count("# >>> proxyspy") == 1


def test_remove_managed_hosts_pid_removes_only_own(tmp_path, pids):
    """Clean exit strips only our own PID's block, leaving a concurrent live
    session's block in place."""
    hosts_path = tmp_path / "hosts"
    foreign, _ = pids
    mine = os.getpid()
    hosts_path.write_text(
        "127.0.0.1 localhost\n" + _fenced("a.example.com", foreign) + _fenced("b.example.com", mine)
    )

    assert proxyspy.remove_managed_hosts(hosts_path=str(hosts_path), pid=mine) is True

    text = hosts_path.read_text()
    assert "127.0.0.1 a.example.com" in text
    assert "b.example.com" not in text


def test_remove_managed_hosts_drop_dead_keeps_live(tmp_path, pids):
    """Startup self-heal removes a stale block but never a live foreign one."""
    hosts_path = tmp_path / "hosts"
    foreign, dead = pids
    hosts_path.write_text(
        "127.0.0.1 localhost\n" + _fenced("a.example.com", foreign) + _fenced("b.example.com", dead)
    )

    assert proxyspy.remove_managed_hosts(hosts_path=str(hosts_path), drop_dead=True) is True

    text = hosts_path.read_text()
    assert "127.0.0.1 a.example.com" in text
    assert "b.example.com" not in text


def test_remove_managed_hosts_drop_dead_noop_when_all_live(tmp_path, pids):
    hosts_path = tmp_path / "hosts"
    foreign, _ = pids
    hosts_path.write_text("127.0.0.1 localhost\n" + _fenced("a.example.com", foreign))

    assert proxyspy.remove_managed_hosts(hosts_path=str(hosts_path), drop_dead=True) is False
    assert "127.0.0.1 a.example.com" in hosts_path.read_text()


def test_remove_managed_hosts_restore_removes_live_block(tmp_path, pids):
    """--restore-hosts removes every proxyspy block, live or not."""
    hosts_path = tmp_path / "hosts"
    foreign, _ = pids
    hosts_path.write_text("127.0.0.1 localhost\n" + _fenced("a.example.com", foreign))

    assert proxyspy.remove_managed_hosts(hosts_path=str(hosts_path)) is True
    assert hosts_path.read_text() == "127.0.0.1 localhost\n"


def test_remove_managed_hosts_drop_dead_removes_recycled_own_pid(tmp_path, pids):
    """Self-heal removes a stale block tagged with our own PID: the PID was
    recycled from a run that died uncleanly, since this run has not written
    its block yet. (Our own PID is alive, so a plain liveness check would
    wrongly keep it.)"""
    hosts_path = tmp_path / "hosts"
    foreign, _ = pids
    hosts_path.write_text(
        "127.0.0.1 localhost\n"
        + _fenced("a.example.com", foreign)
        + _fenced("stale.example.com", os.getpid())
    )

    assert proxyspy.remove_managed_hosts(hosts_path=str(hosts_path), drop_dead=True) is True

    text = hosts_path.read_text()
    assert "127.0.0.1 a.example.com" in text
    assert "stale.example.com" not in text


def test_strip_managed_block_unterminated_tagged_before_other_block(pids):
    """An unterminated tagged block followed by another PID's complete block
    must not be matched as one block spanning both (which would delete the
    live block and any user entries in between)."""
    foreign, dead = pids
    text = (
        "127.0.0.1 localhost\n"
        "# >>> proxyspy %d >>>\n"
        "127.0.0.1 stale.example.com\n"
        "10.0.0.5 user-entry\n" % dead
    ) + _fenced("live.example.com", foreign)
    stripped = proxyspy._strip_managed_block(text, keep=proxyspy._keep_live_foreign_block)
    assert stripped == text
    # Without a keep predicate only the complete block is removed.
    assert proxyspy._strip_managed_block(text) == text[: text.index("# >>> proxyspy %d" % foreign)]


def test_strip_managed_block_mismatched_fence_pids():
    """Begin/end fences naming different PIDs do not form a block."""
    text = "# >>> proxyspy 111 >>>\n127.0.0.1 a.example.com\n# <<< proxyspy 222 <<<\n"
    assert proxyspy._strip_managed_block(text) == text


def test_strip_managed_block_end_fence_must_end_line():
    text = "# >>> proxyspy 111 >>>\n127.0.0.1 a.example.com\n# <<< proxyspy 111 <<< junk\n"
    assert proxyspy._strip_managed_block(text) == text


@pytest.mark.skipif(os.name != "posix", reason="hosts file locking is POSIX-only")
def test_concurrent_removals_do_not_resurrect_blocks(tmp_path, monkeypatch, pids):
    """Two sessions cleaning up at once must not each write back the other's
    block. A delay between each call's read and write makes the race
    deterministic without the lock: both would read A+B, one writes B, the
    other writes A, and a removed block comes back."""
    foreign, _ = pids
    mine = os.getpid()
    hosts_path = tmp_path / "hosts"
    hosts_path.write_text(
        "127.0.0.1 localhost\n" + _fenced("a.example.com", mine) + _fenced("b.example.com", foreign)
    )

    real_strip = proxyspy._strip_managed_block

    def slow_strip(text, keep=None):
        result = real_strip(text, keep=keep)
        time.sleep(0.3)
        return result

    monkeypatch.setattr(proxyspy, "_strip_managed_block", slow_strip)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda pid: proxyspy.remove_managed_hosts(hosts_path=str(hosts_path), pid=pid),
                [mine, foreign],
            )
        )

    assert results == [True, True]
    assert hosts_path.read_text() == "127.0.0.1 localhost\n"
    assert (tmp_path / ("hosts" + proxyspy.HOSTS_LOCK_SUFFIX)).exists()


@pytest.mark.skipif(os.name == "posix", reason="checks the non-POSIX guard")
def test_pid_alive_refuses_off_posix():
    with pytest.raises(NotImplementedError):
        proxyspy._pid_alive(os.getpid())


@pytest.mark.skipif(os.name != "posix", reason="PID liveness check is POSIX-only")
def test_pid_alive():
    assert proxyspy._pid_alive(os.getpid()) is True
    assert proxyspy._pid_alive(_dead_pid()) is False


@pytest.mark.skipif(os.name != "posix", reason="permission bits are POSIX-only")
def test_atomic_write_preserves_permissions(tmp_path):
    hosts_path = tmp_path / "hosts"
    bak_path = tmp_path / "hosts.bak"
    hosts_path.write_text("127.0.0.1 localhost\n")
    os.chmod(hosts_path, 0o644)

    proxyspy.write_managed_hosts(
        ["example.com"], hosts_path=str(hosts_path), bak_path=str(bak_path)
    )

    assert (os.stat(hosts_path).st_mode & 0o777) == 0o644


def _run_proxyspy_cli(*extra_args):
    """Invoke proxyspy directly (no proxy startup) to check argparse validation."""
    cmd = ["python", find_proxyspy()] + list(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10)


# On Windows the POSIX-only guard for --manage-hosts/--restore-hosts fires
# first, so these mode-combination messages are never reached; skip there.
@pytest.mark.skipif(os.name != "posix", reason="hosts flags are POSIX-only")
def test_manage_hosts_requires_reverse():
    result = _run_proxyspy_cli("--manage-hosts", "--", "echo", "hi")
    assert result.returncode == 2
    assert "--manage-hosts requires --reverse" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="hosts flags are POSIX-only")
def test_restore_hosts_rejects_reverse():
    result = _run_proxyspy_cli("--restore-hosts", "--reverse")
    assert result.returncode == 2
    assert "--restore-hosts is standalone" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="hosts flags are POSIX-only")
def test_restore_hosts_rejects_command():
    result = _run_proxyspy_cli("--restore-hosts", "--", "echo", "hi")
    assert result.returncode == 2
    assert "--restore-hosts is standalone" in result.stderr


# The root requirement is only enforced on POSIX (os.geteuid); on Windows the
# check is skipped entirely, so these tests only make sense there.
@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="root check is POSIX-only and can't fire when already root",
)
def test_restore_hosts_requires_root():
    result = _run_proxyspy_cli("--restore-hosts")
    assert result.returncode == 2
    assert "requires root" in result.stderr
    assert "modifying /etc/hosts" in result.stderr


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="root check is POSIX-only and can't fire when already root",
)
def test_reverse_default_port_requires_root():
    """--reverse with no explicit --port defaults to 443, a privileged port."""
    result = _run_proxyspy_cli("--reverse", "--prepare-host", "example.com")
    assert result.returncode == 2
    assert "requires root" in result.stderr
    assert "binding privileged port 443" in result.stderr


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="root check is POSIX-only and can't fire when already root",
)
def test_reverse_manage_hosts_requires_root_for_both_reasons():
    result = _run_proxyspy_cli("--reverse", "--manage-hosts", "--intercept-host", "example.com")
    assert result.returncode == 2
    assert "modifying /etc/hosts" in result.stderr
    assert "binding privileged port 443" in result.stderr


def _hosts_integration_skip_reason():
    if os.name != "posix":
        return "requires POSIX"
    if os.geteuid() != 0:
        return "requires root"
    if os.environ.get("PROXYSPY_TEST_HOSTS") != "1":
        return "set PROXYSPY_TEST_HOSTS=1 to run (mutates real /etc/hosts)"
    return None


@pytest.mark.skipif(
    _hosts_integration_skip_reason() is not None, reason=_hosts_integration_skip_reason() or ""
)
class TestManageHostsIntegration:
    """Root-gated, opt-in tests that mutate the real /etc/hosts. Runs in CI
    on non-Windows runners via a dedicated sudo step; run locally with:
    sudo PROXYSPY_TEST_HOSTS=1 pytest -v tests -k ManageHostsIntegration
    """

    HOST = "proxyspy-test-host.invalid"

    def test_lifecycle(self, tmp_path):
        original = Path(proxyspy.HOSTS_PATH).read_text()
        harness = ReverseHarness(tmp_path)
        try:
            harness.start(
                "--manage-hosts",
                "--intercept-host",
                self.HOST,
                "--return-code",
                "418",
            )
            hosts_text = Path(proxyspy.HOSTS_PATH).read_text()
            assert proxyspy._MANAGED_BLOCK_RE.search(hosts_text)
            assert f"127.0.0.1 {self.HOST}" in hosts_text

            sock = harness.connect(self.HOST)
            sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {self.HOST}\r\nConnection: close\r\n\r\n".encode()
            )
            response = sock.recv(4096)
            sock.close()
            assert b"418" in response
        finally:
            harness.stop()

        assert Path(proxyspy.HOSTS_PATH).read_text() == original

    def test_map_host_is_managed(self, tmp_path):
        """A --map host alone is enough for --manage-hosts to redirect it."""
        original = Path(proxyspy.HOSTS_PATH).read_text()
        harness = ReverseHarness(tmp_path)
        try:
            # The mapping is never dialed; an explicit map skips resolution, so
            # the unresolvable .invalid host is fine.
            harness.start("--manage-hosts", "--map", f"{self.HOST}=http://127.0.0.1:9")
            assert f"127.0.0.1 {self.HOST}" in Path(proxyspy.HOSTS_PATH).read_text()
        finally:
            harness.stop()

        assert Path(proxyspy.HOSTS_PATH).read_text() == original

    def test_self_heal_after_sigkill(self, tmp_path):
        # --return-code makes HOST intercept-only, so proxyspy never tries to
        # resolve the unresolvable .invalid upstream at startup.
        original = Path(proxyspy.HOSTS_PATH).read_text()
        harness = ReverseHarness(tmp_path)
        try:
            harness.start("--manage-hosts", "--intercept-host", self.HOST, "--return-code", "418")
            assert proxyspy._MANAGED_BLOCK_RE.search(Path(proxyspy.HOSTS_PATH).read_text())

            harness.process.kill()
            harness.process.wait(timeout=5)
            assert proxyspy._MANAGED_BLOCK_RE.search(Path(proxyspy.HOSTS_PATH).read_text())

            harness2 = ReverseHarness(tmp_path)
            try:
                harness2.start(
                    "--manage-hosts", "--intercept-host", self.HOST, "--return-code", "418"
                )
                assert "Self-heal: removed a stale /etc/hosts block" in harness2.logs()
            finally:
                harness2.stop()
        finally:
            harness.stop()

        assert Path(proxyspy.HOSTS_PATH).read_text() == original
