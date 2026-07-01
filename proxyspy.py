#!/usr/bin/env python3

# Copyright (c) 2024, Anaconda, Inc.
# This file is distributed under a 3-clause BSD license.
# For license details, see https://github.com/anaconda/proxyspy/blob/main/LICENSE.txt

"""HTTPS debugging proxy that logs or intercepts HTTPS requests.

Runs in one of two modes:

* Forward mode (default): launches a proxy server and runs a command with the
  proxy environment variables set, forwarding HTTPS requests while logging
  headers and content, or intercepting requests and returning specified
  responses.
* Reverse mode (--reverse): runs standalone, listening on 127.0.0.1 (default
  port 443) and reading the target host from the TLS SNI field. Point the
  target hostnames at 127.0.0.1 in /etc/hosts to monitor clients that ignore
  proxy environment variables. Start proxyspy *before* editing /etc/hosts so it
  can resolve the real upstream addresses while DNS is still clean.

Manages certificates automatically and supports concurrent connections. The
script relies on the cryptography library to generate SSL certificates for the
proxy, but deliberately avoids other third-party dependencies.

Arguments:
    --logfile, -l FILE    Write logs to FILE instead of stdout
    --port, -p PORT       Listen on PORT (default: auto-select; 443 in reverse)
    --keep-certs          Keep certificates in current directory
    --delay TIME          Emulate a connection delay of TIME seconds
    --return-code, -r N   Return status code N for all requests
    --return-header H     Add header H to responses (can repeat)
    --return-data DATA    Return DATA as response body
    --intercept-host HOST Only intercept requests to HOST (can repeat)
    --prepare-host HOST   Pre-generate the certificate for HOST (can repeat)
    --reverse             Standalone reverse/transparent proxy (no command)
    --manage-hosts        Auto-manage /etc/hosts redirects (reverse mode; POSIX only)
    --restore-hosts       Remove any proxyspy-managed /etc/hosts block and exit
    --cert-dir DIR        Persistent certificate directory (reverse: ~/.proxyspy)
    --map HOST=IP         Pin the real upstream IP for HOST (reverse; can repeat)
    --upstream-port PORT  Upstream port to dial in reverse mode (default: 443)

Examples:
    # Log all HTTPS requests to test.log:
    ./proxyspy.py --logfile test.log -- curl https://httpbingo.org/ip

    # Return 404 for all requests, but with a half-second delay:
    ./proxyspy.py --return-code 404 --delay 0.5 -- python my_script.py

    # Return custom response with headers and body:
    ./proxyspy.py --return-code 200 \\
                  --return-header "Content-Type: application/json" \\
                  --return-data '{"status": "ok"}' \\
                  -- ./my_script.py

    # Standalone reverse proxy monitoring conda traffic (run as root for 443):
    #   1. sudo ./proxyspy.py --reverse --prepare-host repo.anaconda.com -l spy.log
    #   2. trust ~/.proxyspy/cert.pem, then add "127.0.0.1 repo.anaconda.com"
    #      to /etc/hosts and run your client; Ctrl-C and revert /etc/hosts after
"""

import argparse
import atexit
import ipaddress
import logging
import os
import re
import select
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os.path import isfile, join
from threading import Lock, Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Modified by our pre-commit hook
__version__ = "0.1.5.post35"

# _forward_data buffer size
BUFFER_SIZE = 65536
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
CONNECTION_FORMAT = "[%s/%.3f/%.3f] %s"  # cid, split, elapsed, message

logger = logging.getLogger(__name__)

#
# Certificate operations
#


CERT_DIR = None
CA_CERT = None
CA_KEY = None
# Track which host certificates we've logged about to prevent duplicate messages
CERT_READ = set()


def read_or_create_cert(host=None):
    """Reads and/or creates the SSL certificates for the proxy, including
    both the CA certificate and the host certificates signed with it. If
    --keep-certs is set, then certificates will be saved between runs."""

    global CA_CERT
    global CA_KEY

    is_CA = host is None
    if is_CA:
        logger.info("Requested CA certificate")
    else:
        assert CA_CERT and CA_KEY
        logger.info("Requested certificate for %s", host)

    assert CERT_DIR
    cert_path = join(CERT_DIR, "cert.pem" if is_CA else "%s-cert.pem" % host)
    key_path = join(CERT_DIR, "key.pem" if is_CA else "%s-key.pem" % host)

    # return quickly if the files already exist
    if isfile(cert_path) and isfile(key_path):
        if is_CA:
            logger.info("Using existing CA certificate")
            with open(cert_path, "rb") as f:
                CA_CERT = x509.load_pem_x509_certificate(f.read())
            with open(key_path, "rb") as f:
                CA_KEY = serialization.load_pem_private_key(f.read(), password=None)
        elif host not in CERT_READ:
            logger.info("Using existing host certificate for %s", host)
            CERT_READ.add(host)
        return cert_path, key_path
    logger.debug("Certificate not cached; generating")

    # Generate CSR-like data
    hostname = "Debug Proxy CA" if is_CA else host
    host_info = [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
    if is_CA:
        host_info.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Debug Proxy"))
    name = x509.Name(host_info)
    logger.debug("Name generated")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pub = key.public_key()
    logger.debug("Private key generated")

    if not host:
        CA_KEY = key
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name if is_CA else CA_CERT.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        # Use UTC (cryptography treats naive datetimes as UTC) and backdate a
        # few minutes so clock skew between proxy and client can't make a
        # freshly minted certificate appear "not yet valid".
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_CA, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_CA,  # True for CA, False for host
                crl_sign=is_CA,  # True for CA, False for host
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if is_CA:
        # Enable certificate signing
        cert = cert.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub),
            critical=False,
        )
    else:
        # Host-specific extensions
        cert = (
            cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(CA_KEY.public_key()),
                critical=False,
            )
        )
    logger.debug("Certificate constructed")

    # Sign with CA key
    cert = cert.sign(CA_KEY, hashes.SHA256())
    logger.debug("Certificate signed")
    if is_CA:
        CA_CERT = cert

    # Save and return the certificate and private key in PEM format
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Write to files
    with open(key_path, "wb") as f:
        f.write(key_pem)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    logger.debug("Certificate written to disk")

    return cert_path, key_path


#
# Server implementation
#


class MyHTTPServer(ThreadingHTTPServer):
    """Thread-per-connection server, used for both the forward (ProxyHandler)
    and reverse (ReverseHandler) modes; the handler decides how to read the
    target host. (A TCPServer happily serves a non-HTTP handler.)"""

    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Connection counter
        self.counter = 0
        # Lock for single-threaded operations
        self.lock = Lock()
        # Interception settings
        self.intercept_mode = False
        self.intercept_hosts = []
        self.return_code = 200  # Default if in intercept mode
        self.return_headers = []  # List of (name, value) tuples
        self.return_data = ""  # Response body
        self.delay = 0
        # Reverse mode only: host -> (ip, port) upstreams and the SNI context
        self.upstream = {}
        self.base_context = None


class ConnLoggingMixin:
    """Per-connection timing and logging shared by the forward and reverse handlers."""

    def setup(self):
        self.start_time = time.perf_counter()
        self.last_time = self.start_time
        with self.server.lock:
            self.server.counter += 1
            self.cid = "%04d" % self.server.counter
        super().setup()

    def _log(self, *args, **kwargs):
        """Log message with elapsed time since first message for this connection ID"""
        level = kwargs.pop("level", "info")
        n_time = time.perf_counter()
        d1 = n_time - self.last_time
        d2 = n_time - self.start_time
        fmt = CONNECTION_FORMAT % (self.cid, d1, d2, args[0])
        getattr(logger, level)(fmt, *args[1:], **kwargs)
        self.last_time = n_time

    def _multiline_log(self, blob, firstline=None, direction=None, include_binary=False):
        """Split binary/text data into lines for logging, logging text and remaining byte count"""
        lines = []
        is_binary = False
        if firstline is not None:
            lines.append(firstline)
        if isinstance(blob, bytes):
            while blob:
                ndx = blob.find(b"\r\n")
                line = blob if ndx < 0 else blob[:ndx]
                try:
                    line = line.decode("iso-8859-1")
                    blob = b"" if ndx < 0 else blob[ndx + 2 :]  # noqa
                    if not line:
                        is_binary = True
                        break
                    lines.append(line)
                except UnicodeDecodeError:
                    is_binary = True
                    break
        else:
            lines.extend(str(blob).strip().splitlines())
            blob = ""
        if include_binary and (is_binary or not blob):
            if blob:
                lines.append("<+ %d bytes>" % len(blob))
                blob = ""
            else:
                lines.append("<no data>")
            is_binary = False
        if direction:
            lines[0] = "[%s] %s" % (direction, lines[0])
        self._log("\n  | ".join(lines))
        return len(blob), is_binary

    def _enforce_delay(self):
        """Emulate a connection delay of self.server.delay seconds, if configured."""
        if self.server.delay:
            self._log("Enforcing %gs delay", self.server.delay)
            current = self.last_time
            finish = self.start_time + self.server.delay
            while finish - current > 0.001:
                time.sleep(finish - current)
                current = time.perf_counter()
            self._log("End of connection delay")

    def _serve_tunnel(self, client, host, upstream_addr):
        """Service a decrypted client tunnel: either return a canned response
        (interception) or forward to the real upstream while logging traffic.

        host drives intercept matching and the upstream SNI/verification name;
        upstream_addr is the (address, port) actually dialed when forwarding,
        which may differ from host (e.g. a pre-resolved IP in reverse mode)."""
        should_intercept = self.server.intercept_mode
        if should_intercept and self.server.intercept_hosts:
            should_intercept = host in self.server.intercept_hosts
            if should_intercept:
                self._log("Host %s found in intercept list" % host)
            else:
                self._log("Host %s not found in intercept list, forwarding" % host)

        if should_intercept:
            # Read the decrypted request
            request = t_request = client.recv(BUFFER_SIZE)
            data = (self.server.return_data or "").encode("utf-8")
            while len(t_request) == BUFFER_SIZE:
                t_request = client.recv(BUFFER_SIZE)
                request += t_request
            self._multiline_log(request, direction="C->P", include_binary=True)

            # Build and send custom response headers
            response = ["HTTP/1.1 %d Intercepted" % self.server.return_code]
            response.extend(": ".join(h) for h in self.server.return_headers)
            if data:
                response.append("Content-Length: %d" % len(data))
            response.extend(("", ""))
            response = "\r\n".join(response).encode("iso-8859-1")
            self._multiline_log(response, direction="P->C", include_binary=False)
            client.sendall(response)

            # Send response data if provided
            if data:
                client.sendall(data)
                self._log("[P->C] %d data bytes delivered", len(data))
        else:
            # Create SSL context for the server connection (verify remote)
            remote = None
            try:
                self._log("About to create connection to %s:%d", *upstream_addr)
                remote = socket.create_connection(upstream_addr)
                self._log("About to wrap socket")
                server_context = ssl.create_default_context()
                remote = server_context.wrap_socket(remote, server_hostname=host)
                self._log("[P<>S] SSL handshake completed")
                # Forward all requests to the real server
                self._forward_data(client, remote)
            finally:
                if remote:
                    remote.close()

    def _forward_data(self, client, remote):
        """Forward data between client and remote, logging headers and tracking binary data size"""

        def forward(source, destination, direction, bcount, is_binary):
            try:
                data = source.recv(BUFFER_SIZE)
                if not data:
                    return False, bcount, is_binary
            except (OSError, ssl.SSLError) as exc:
                self._log("%s: Receive error: %s", direction, exc, level="error")
                return False, bcount, is_binary

            if is_binary:
                bcount += len(data)
            else:
                # First chunk contains headers; subsequent chunks may be binary
                ncount, is_binary = self._multiline_log(data, direction=direction)
                bcount += ncount

            try:
                destination.sendall(data)
                return True, bcount, is_binary
            except Exception as exc:
                self._log("%s: Send error: %s", direction, exc, level="error")
                return False, bcount, is_binary

        # Track binary data for each direction separately
        c_total = r_total = 0
        c_binary = r_binary = False
        while True:
            # 1 second timeout to check for connection closure
            r, w, e = select.select([client, remote], [], [], 1.0)
            if not r:
                break
            if client in r:
                success, c_total, c_binary = forward(client, remote, "C->S", c_total, c_binary)
                if not success:
                    break
            if remote in r:
                success, r_total, r_binary = forward(remote, client, "S->C", r_total, r_binary)
                if not success:
                    break

        # Deliver final binary totals
        if c_total:
            self._log("[C->S] %d data bytes sent", c_total)
        if r_total:
            self._log("[S->C] %d data bytes received", r_total)


class ProxyHandler(ConnLoggingMixin, BaseHTTPRequestHandler):
    """Forward-proxy handler: clients reach us via CONNECT and the proxy
    environment variables, so the target host arrives on the request line."""

    def log_message(self, format, *args):
        """Override to prevent access log messages from appearing on stderr"""
        pass

    def do_CONNECT(self):
        self._multiline_log(
            self.headers,
            firstline=self.requestline,
            direction="C->P",
            include_binary=True,
        )
        host, port = self.path.split(":")

        client = None
        error_code = 0
        error_msg = None

        try:
            # Obtain MITM certificates for this host
            with self.server.lock:
                cert_file, key_file = read_or_create_cert(host)

            self._enforce_delay()

            # Establish tunnel
            self.send_response(200, "Connection Established")
            self._multiline_log(
                b"".join(self._headers_buffer) + b"\r\n",
                direction="P->C",
                include_binary=True,
            )
            self.end_headers()

            # Create SSL context for the client connection (MITM certificate)
            client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            client_context.load_cert_chain(cert_file, key_file)
            client = client_context.wrap_socket(self.connection, server_side=True)
            self._log("[C<>P] SSL handshake completed")

            # Forward mode resolves the host normally (/etc/hosts untouched here)
            self._serve_tunnel(client, host, (host, int(port)))

        except ssl.SSLError as ssl_err:
            self._log("SSL error: %s", ssl_err, level="error")
            error_code, error_msg = 502, "SSL Handshake Failed"
        except OSError as sock_err:
            self._log("Socket error: %s", sock_err, level="error")
            error_code, error_msg = 504, "Gateway Timeout"
        except Exception as exc:
            self._log("CONNECT error: %s", exc, level="error")
            error_code, error_msg = 502, "Proxy Error"
        finally:
            if error_code:
                try:
                    self.send_error(error_code, error_msg)
                except Exception:
                    # If connection is already dead, sending an
                    # error would raise socket.error
                    pass
            self.close_connection = True
            if client:
                client.close()
            self._log("Connection closed")


class ReverseHandler(ConnLoggingMixin, socketserver.BaseRequestHandler):
    """Transparent/reverse handler: clients connect straight to us (via an
    /etc/hosts redirect) and open TLS immediately, so the target host comes
    from the TLS SNI field rather than a CONNECT line."""

    def handle(self):
        client = None
        try:
            self._enforce_delay()

            # The SNI callback stamps the requested hostname on the socket as it
            # selects the per-host certificate during the handshake.
            client = self.server.base_context.wrap_socket(self.request, server_side=True)
            host = getattr(client, "proxyspy_host", None)
            self._log("[C<>P] SSL handshake completed (SNI: %s)", host)
            if not host:
                self._log("No SNI hostname provided by client; closing", level="error")
                return

            upstream = self.server.upstream.get(host)
            if upstream is None:
                # Not a declared host: fall back to resolving the SNI name. This
                # only succeeds if it is not redirected to us in /etc/hosts.
                upstream = (host, 443)
            self._serve_tunnel(client, host, upstream)

        except ssl.SSLError as ssl_err:
            self._log("SSL error: %s", ssl_err, level="error")
        except OSError as sock_err:
            self._log("Socket error: %s", sock_err, level="error")
        except Exception as exc:
            self._log("Reverse connection error: %s", exc, level="error")
        finally:
            if client:
                client.close()
            self._log("Connection closed")


def find_free_port():
    """Find a free port that's not in TIME_WAIT state."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))  # Let OS choose port
        return s.getsockname()[1]


def make_sni_context():
    """Build the server-side SSL context used by reverse mode. Its SNI callback
    records the requested hostname on the connection and swaps in that host's
    MITM certificate, minting one on first sight."""
    base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    host_contexts = {}

    def sni_callback(sock, server_name, ctx):
        sock.proxyspy_host = server_name
        if not server_name:
            return
        host_ctx = host_contexts.get(server_name)
        if host_ctx is None:
            cert_file, key_file = read_or_create_cert(server_name)
            host_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            host_ctx.load_cert_chain(cert_file, key_file)
            host_contexts[server_name] = host_ctx
        sock.context = host_ctx

    base.sni_callback = sni_callback
    return base


def resolve_upstream(host, port, overrides):
    """Resolve host to a real (ip, port) upstream, preferring --map overrides.
    Refuses a loopback result unless pinned, since that means the host is
    already redirected to us in /etc/hosts and forwarding would loop back."""
    if host in overrides:
        return overrides[host], port
    ip = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
    if ipaddress.ip_address(ip).is_loopback:
        raise RuntimeError(
            "%s already resolves to a loopback address (%s); remove it from "
            "/etc/hosts before starting, or pin it with --map %s=<ip>" % (host, ip, host)
        )
    return ip, port


def _sudo_pw():
    """pwd entry for the invoking user when running under sudo, or None if not
    under sudo (or not on a POSIX system, or the user no longer exists)."""
    if os.name != "posix":
        return None
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return None
    import pwd

    try:
        return pwd.getpwnam(sudo_user)
    except KeyError:
        return None


def default_cert_dir():
    """~/.proxyspy, resolving the invoking user's home even under sudo."""
    pw = _sudo_pw()
    home = pw.pw_dir if pw else os.path.expanduser("~")
    return join(home, ".proxyspy")


def _chown_to_sudo_user(path):
    """When running as root under sudo, hand the persistent cert directory and
    its contents to the invoking user, so the CA stays readable/writable from
    their normal unprivileged sessions rather than being locked to root. This
    also repairs a directory left root-owned by an earlier run."""
    pw = _sudo_pw()
    if pw is None or os.geteuid() != 0:
        return
    for root, dirs, files in os.walk(path):
        for target in [root] + [join(root, name) for name in dirs + files]:
            try:
                os.chown(target, pw.pw_uid, pw.pw_gid)
            except OSError as exc:
                logger.debug("Could not chown %s to %s: %s", target, pw.pw_name, exc)


#
# /etc/hosts management (--manage-hosts / --restore-hosts)
#

HOSTS_PATH = "/etc/hosts"
HOSTS_BAK = "/etc/hosts.proxyspy.bak"
FENCE_BEGIN = "# >>> proxyspy >>>"
FENCE_END = "# <<< proxyspy <<<"

# Non-greedy + DOTALL so multiple blocks are each stripped individually. An
# unmatched FENCE_BEGIN (no following FENCE_END) is deliberately left alone
# rather than consuming the rest of the file.
_MANAGED_BLOCK_RE = re.compile(
    re.escape(FENCE_BEGIN) + r".*?" + re.escape(FENCE_END) + r"\n?", re.DOTALL
)


def _strip_managed_block(text):
    """Remove the fenced proxyspy block(s) from text, if present. Pure
    string in/string out so it is trivially unit-testable; idempotent if no
    block is present."""
    return _MANAGED_BLOCK_RE.sub("", text)


def _fenced_block(hosts):
    """Build the fenced block text (including trailing newline) for hosts."""
    lines = [FENCE_BEGIN, "# Managed by proxyspy (PID %d). Do not edit by hand." % os.getpid()]
    lines.extend("127.0.0.1 %s" % host for host in sorted(hosts))
    lines.append(FENCE_END)
    return "\n".join(lines) + "\n"


def _atomic_write(path, text):
    """Write text to path atomically: temp file in the same directory,
    flush+fsync, then os.replace() so the file is never observed
    half-written.

    mkstemp creates the temp file mode 0600; without correcting that before
    os.replace(), the live file would silently become unreadable by every
    unprivileged process. Match path's existing mode (falling back to 0644
    if it doesn't exist yet, e.g. a fresh file in tests). Ownership is left
    as-is (whoever runs proxyspy), which is correct since reverse mode
    already needs root for port 443.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".proxyspy-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        try:
            mode = os.stat(path).st_mode & 0o777
        except FileNotFoundError:
            mode = 0o644
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def write_managed_hosts(hosts, hosts_path=HOSTS_PATH, bak_path=HOSTS_BAK):
    """Write the fenced managed block for hosts into hosts_path, replacing
    any existing block. Backs up hosts_path to bak_path once, on first
    mutation; the backup is never overwritten or touched by removal."""
    try:
        with open(hosts_path) as f:
            current = f.read()
    except FileNotFoundError:
        current = ""
    else:
        if not os.path.exists(bak_path):
            shutil.copy2(hosts_path, bak_path)
    stripped = _strip_managed_block(current)
    if stripped and not stripped.endswith("\n"):
        stripped += "\n"
    _atomic_write(hosts_path, stripped + _fenced_block(hosts))


def remove_managed_hosts(hosts_path=HOSTS_PATH):
    """Strip the managed block from hosts_path if present. Returns True if
    a block was found and removed, False if the file was already clean."""
    try:
        with open(hosts_path) as f:
            current = f.read()
    except FileNotFoundError:
        return False
    stripped = _strip_managed_block(current)
    if stripped == current:
        return False
    _atomic_write(hosts_path, stripped)
    return True


def configure_intercept(server, args):
    """Apply --return-* / --intercept-host options to a server. Returns False
    on a malformed --return-header."""
    server.delay = max(0, args.delay)
    if any(x is not None for x in [args.return_code, args.return_data]) or args.return_header:
        server.intercept_mode = True
        server.return_code = args.return_code or 200
        server.return_data = args.return_data or ""
        server.intercept_hosts = args.intercept_host or []

        server.return_headers = []
        for header in args.return_header or []:
            try:
                name, value = header.split(":", 1)
                server.return_headers.append((name.strip(), value.strip()))
            except ValueError:
                logger.error("Invalid header format: %s", header)
                return False
    return True


#
# Command-line interface
#


def main():
    global CERT_DIR

    # Parse arguments
    parser = argparse.ArgumentParser(
        description="HTTPS debugging proxy that logs or intercepts HTTPS requests"
    )
    parser.add_argument("--logfile", "-l", help="File to write logs to (defaults to stdout)")
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        help="Port for the proxy server (default: auto-select, or 443 in --reverse mode)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        action="store",
        default=0,
        help="Add a delay, in seconds, to each connection request, to test connection issues.",
    )
    parser.add_argument(
        "--keep-certs",
        action="store_true",
        help="Keep certificates in current directory instead of using a temporary directory",
    )
    parser.add_argument(
        "--reverse",
        action="store_true",
        help="Run as a standalone reverse/transparent proxy: listen on 127.0.0.1 "
        "(default port 443) and read the target host from TLS SNI, instead of "
        "running a command behind proxy environment variables. Redirect the "
        "target hostnames to 127.0.0.1 in /etc/hosts.",
    )
    parser.add_argument(
        "--manage-hosts",
        action="store_true",
        help="Automatically add/remove the /etc/hosts redirects for the declared "
        "hosts for the lifetime of this run (reverse mode only; POSIX only).",
    )
    parser.add_argument(
        "--restore-hosts",
        action="store_true",
        help="Remove any proxyspy-managed block from /etc/hosts and exit "
        "(standalone; POSIX only; does not require --reverse).",
    )
    parser.add_argument(
        "--cert-dir",
        help="Directory for the persistent CA and host certificates "
        "(reverse mode default: ~/.proxyspy)",
    )
    parser.add_argument(
        "--map",
        action="append",
        metavar="HOST=IP",
        help="Pin the real upstream IP for HOST, bypassing DNS (reverse mode; can be repeated). "
        "Use this when HOST is already redirected to 127.0.0.1 in /etc/hosts.",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        default=443,
        help="Port to connect to on the real upstream servers (reverse mode; default: 443)",
    )
    parser.add_argument(
        "--return-code",
        "-r",
        type=int,
        help="HTTP status code to return for all requests",
    )
    parser.add_argument(
        "--intercept-host",
        action="append",
        help="Only intercept requests from this host (e.g. 'conda.anaconda.org') (can be repeated)",
    )
    parser.add_argument(
        "--prepare-host",
        action="append",
        help="Prepare the SSL certificate for this host in advance, to reduce the "
        "first connection delay (can be repeated)",
    )
    parser.add_argument(
        "--return-header",
        action="append",
        help='Response header in format "Name: Value" (can be repeated)',
    )
    parser.add_argument("--return-data", help="Response body to return")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "command", nargs="*", help="Command to run and its arguments (forward mode only)"
    )
    args = parser.parse_args()

    # Validate mode/command combination
    if (args.manage_hosts or args.restore_hosts) and os.name != "posix":
        parser.error(
            "--manage-hosts/--restore-hosts are POSIX-only; edit /etc/hosts manually "
            "on this platform"
        )
    if args.manage_hosts and not args.reverse:
        parser.error("--manage-hosts requires --reverse")
    if args.restore_hosts and (args.reverse or args.command):
        parser.error(
            "--restore-hosts is standalone and cannot be combined with --reverse or a command"
        )
    if args.reverse and args.command:
        parser.error("a command cannot be given in --reverse mode")
    if not args.reverse and not args.restore_hosts and not args.command:
        parser.error("a command is required (or use --reverse for standalone mode)")

    # Fail fast and cleanly if this invocation needs root, rather than
    # surfacing a raw PermissionError partway through startup (binding port
    # 443, or writing /etc/hosts).
    if os.name == "posix" and os.geteuid() != 0:
        if args.port is None:
            port_needed = 443 if args.reverse else None
        elif args.port == 0:
            port_needed = None  # auto-select always lands on an unprivileged port
        else:
            port_needed = args.port
        reasons = []
        if args.manage_hosts or args.restore_hosts:
            reasons.append("modifying /etc/hosts")
        if args.reverse and port_needed is not None and port_needed < 1024:
            reasons.append("binding privileged port %d" % port_needed)
        if reasons:
            parser.error("this requires root (sudo): %s" % " and ".join(reasons))

    # Parse --map HOST=IP overrides
    overrides = {}
    for entry in args.map or []:
        host, sep, ip = entry.partition("=")
        if not sep or not host or not ip:
            parser.error("--map expects HOST=IP, got: %s" % entry)
        overrides[host] = ip

    # Configure logging
    logging_config = {
        "level": logging.DEBUG if args.debug else logging.INFO,
        "format": LOG_FORMAT,
        "handlers": [],
    }
    if args.logfile:
        logging_config["handlers"].append(logging.FileHandler(args.logfile))
    else:
        logging_config["handlers"].append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(**logging_config)

    # Log version info immediately after logging setup
    logger.info("ProxySpy version %s", __version__)

    # --restore-hosts is standalone and needs no certs/port/server setup.
    if args.restore_hosts:
        try:
            removed = remove_managed_hosts()
        except PermissionError as exc:
            logger.error("Cannot modify /etc/hosts: %s", exc)
            return 1
        if removed:
            logger.info("Removed proxyspy-managed block from /etc/hosts")
        else:
            logger.info("No proxyspy-managed block found in /etc/hosts; nothing to do")
        return 0

    # Set up certificate generation. Reverse mode persists certificates so the
    # CA can be trusted once and reused; forward mode keeps the old behavior.
    persistent_certs = bool(args.cert_dir or args.reverse)
    if persistent_certs:
        CERT_DIR = args.cert_dir or default_cert_dir()
        os.makedirs(CERT_DIR, exist_ok=True)
    elif args.keep_certs:
        CERT_DIR = os.getcwd()
    else:
        CERT_DIR = tempfile.mkdtemp()

        def cleanup():
            logger.info("Removing temporary certificate directory")
            shutil.rmtree(CERT_DIR, ignore_errors=False)

        atexit.register(cleanup)
    logger.info("Certificate directory: %s", CERT_DIR)
    cert_path, key_path = read_or_create_cert()
    declared_hosts = set(args.intercept_host or ()) | set(args.prepare_host or ())
    for host in declared_hosts:
        read_or_create_cert(host)

    # Under sudo, the persistent cert dir and the certs just written into it are
    # owned by root; hand them back to the invoking user so their unprivileged
    # sessions can still read the CA (and so a later non-sudo run can write here).
    if persistent_certs:
        _chown_to_sudo_user(CERT_DIR)

    # Select the listen port (reverse mode defaults to 443; 0 = auto-select)
    if args.port is None:
        port = 443 if args.reverse else 0
    else:
        port = args.port
    if port == 0:
        port = find_free_port()
        logger.info("Auto-selected port %d", port)

    server = MyHTTPServer(("127.0.0.1", port), ReverseHandler if args.reverse else ProxyHandler)
    if not configure_intercept(server, args):
        return 1

    # Reverse/transparent mode: serve in the foreground until interrupted.
    if args.reverse:
        server.base_context = make_sni_context()

        # Self-heal before resolving: a managed block left behind by a prior
        # run that died uncleanly (e.g. SIGKILL) would make the OS resolver
        # return our own loopback address instead of the real upstream.
        if args.manage_hosts:
            try:
                if remove_managed_hosts():
                    logger.info("Self-heal: removed a stale /etc/hosts block from a previous run")
            except PermissionError as exc:
                logger.error("Cannot modify /etc/hosts: %s", exc)
                return 1

        # A host that is always intercepted never connects upstream, so skip
        # resolving it (avoids a needless lookup and the loopback guard firing).
        intercept_all = server.intercept_mode and not server.intercept_hosts
        for host in declared_hosts:
            if intercept_all or host in server.intercept_hosts:
                continue
            try:
                server.upstream[host] = resolve_upstream(host, args.upstream_port, overrides)
            except (RuntimeError, OSError) as exc:
                logger.error("Cannot resolve upstream for %s: %s", host, exc)
                return 1
            logger.info("Upstream for %s -> %s:%d", host, *server.upstream[host])
        logger.info("Reverse proxy listening on 127.0.0.1:%d", port)
        logger.info("Trust the CA certificate at: %s", cert_path)
        if not args.manage_hosts:
            logger.info(
                "Redirect these hosts to 127.0.0.1 in /etc/hosts: %s",
                ", ".join(sorted(declared_hosts)) or "(none declared)",
            )

        if args.manage_hosts:
            if not declared_hosts:
                logger.warning("--manage-hosts has no declared hosts to write; skipping")
            else:
                try:
                    write_managed_hosts(declared_hosts)
                except PermissionError as exc:
                    logger.error("Cannot modify /etc/hosts: %s", exc)
                    return 1
                logger.info(
                    "Added /etc/hosts redirects for: %s (will be removed on exit)",
                    ", ".join(sorted(declared_hosts)),
                )

                def _handle_sigterm(signum, frame):
                    raise SystemExit(0)

                signal.signal(signal.SIGTERM, _handle_sigterm)

        try:
            server.serve_forever()
        except (KeyboardInterrupt, SystemExit):
            logger.info("Interrupted; shutting down")
        finally:
            server.shutdown()
            server.server_close()
            if args.manage_hosts:
                try:
                    if remove_managed_hosts():
                        logger.info("Removed /etc/hosts redirects")
                except PermissionError as exc:
                    logger.error("Failed to remove /etc/hosts redirects: %s", exc)
        return 0

    server_thread = Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.info("Proxy server started on port %d", port)

    # Proxy configuration
    env = os.environ.copy()
    proxy_host = "http://localhost:%d" % port
    env["HTTPS_PROXY"] = proxy_host
    env["https_proxy"] = proxy_host
    env["HTTP_PROXY"] = proxy_host
    env["http_proxy"] = proxy_host
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""

    # Certificate configuration
    env["CURL_CA_BUNDLE"] = cert_path
    env["SSL_CERT_FILE"] = cert_path
    env["REQUESTS_CA_BUNDLE"] = cert_path
    env["CONDA_SSL_VERIFY"] = cert_path
    logger.info("CA environment variable value: %s", cert_path)

    # Run child process
    returncode = 0
    try:
        process = subprocess.Popen(args.command, env=env)
        returncode = process.wait()
        logger.info("Child process exited with code %d", returncode)
    except Exception as exc:
        logger.error("Error running child process: %s", exc)
        returncode = 255
    finally:
        server.shutdown()
        server.server_close()

    return returncode


if __name__ == "__main__":
    sys.exit(main())
