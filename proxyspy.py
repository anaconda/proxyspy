#!/usr/bin/env python3

# Copyright (c) 2024, Anaconda, Inc.
# This file is distributed under a 3-clause BSD license.
# For license details, see https://github.com/anaconda/proxyspy/blob/main/LICENSE.txt

"""HTTPS debugging proxy that logs or intercepts HTTPS requests.

Launches a proxy server that either forwards HTTPS requests while logging
headers and content, or intercepts requests and returns specified responses.
Manages certificates automatically and supports concurrent connections.
The script relies on the cryptography library to generate SSL certificates
for the proxy, but deliberately avoids other third-party dependencies.

Arguments:
    --logfile, -l FILE    Write logs to FILE instead of stdout
    --port, -p PORT       Listen on PORT (default: 8080)
    --keep-certs          Keep certificates in current directory
    --delay TIME          Emulate a connection delay of TIME seconds
    --return-code, -r N   Return status code N for all requests
    --return-header H     Add header H to responses (can repeat)
    --return-data DATA    Return DATA as response body

Examples:
    # Log all HTTPS requests to test.log:
    ./proxyspy.py --logfile test.log -- curl https://httpbin.org/ip

    # Return 404 for all requests, but with a half-second delay:
    ./proxyspy.py --return-code 404 --delay 0.5 -- python my_script.py

    # Return custom response with headers and body:
    ./proxyspy.py --return-code 200 \\
                  --return-header "Content-Type: application/json" \\
                  --return-data '{"status": "ok"}' \\
                  -- ./my_script.py
"""

import argparse
import atexit
import logging
import os
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os.path import isfile, join
from threading import Lock, Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

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

    if is_CA:
        logger.info("Generating CA certificate")
    else:
        assert CA_CERT and CA_KEY
        logger.info("Generating host certificate for %s", host)

    # Generate CSR-like data
    hostname = "Debug Proxy CA" if is_CA else host
    host_info = [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
    if is_CA:
        host_info.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Debug Proxy"))
    name = x509.Name(host_info)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pub = key.public_key()
    if not host:
        CA_KEY = key
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name if is_CA else CA_CERT.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(datetime.now() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_CA, path_length=None), critical=True)
    )
    if is_CA:
        # Enable certificate signing
        cert = cert.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub),
            critical=False,
        )
    else:
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)

    # Sign with CA key
    cert = cert.sign(CA_KEY, hashes.SHA256())
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

    return cert_path, key_path


#
# Server implementation
#


class MyHTTPServer(ThreadingHTTPServer):
    """HTTPS proxy server with thread-per-connection handling"""

    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Connection counter
        self.counter = 0
        # Lock for single-threaded operations
        self.lock = Lock()
        # Interception settings
        self.intercept_mode = False
        self.return_code = 200  # Default if in intercept mode
        self.return_headers = []  # List of (name, value) tuples
        self.return_data = ""  # Response body


class ProxyHandler(BaseHTTPRequestHandler):

    def setup(self):
        self.start_time = time.perf_counter()
        self.last_time = self.start_time
        with self.server.lock:
            self.server.counter += 1
            self.cid = "%04d" % self.server.counter
        super().setup()

    def log_message(self, format, *args):
        """Override to prevent access log messages from appearing on stderr"""
        pass

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

    def do_CONNECT(self):
        self._multiline_log(
            self.headers,
            firstline=self.requestline,
            direction="C->P",
            include_binary=True,
        )
        host, port = self.path.split(":")

        remote = None
        client = None
        error_code = 0
        error_msg = None

        try:
            # Obtain MITM certificates for this host
            with self.server.lock:
                cert_file, key_file = read_or_create_cert(host)

            if self.server.delay:
                self._log("Enforcing %gs delay", self.server.delay)
                current = self.last_time
                finish = self.start_time + self.server.delay
                while finish - current > 0.001:
                    time.sleep(finish - current)
                    current = time.perf_counter()
                self._log("End of connection delay")

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

            if self.server.intercept_mode:
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
                self._log("About to create connection to %s:%d", host, int(port))
                remote = socket.create_connection((host, int(port)))
                self._log("About to wrap socket")
                server_context = ssl.create_default_context()
                remote = server_context.wrap_socket(remote, server_hostname=host)
                self._log("[P<>S] SSL handshake completed")
                # Forward all requests to the real server
                self._forward_data(client, remote)

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
            if remote:
                remote.close()
            if client:
                client.close()
            self._log("Connection closed")

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
        default=8080,
        help="Port for the proxy server (default: 8080)",
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
        "--return-code",
        "-r",
        type=int,
        help="HTTP status code to return for all requests",
    )
    parser.add_argument(
        "--return-header",
        action="append",
        help='Response header in format "Name: Value" (can be repeated)',
    )
    parser.add_argument("--return-data", help="Response body to return")
    parser.add_argument("command", nargs="+", help="Command to run and its arguments")
    args = parser.parse_args()

    # Configure logging
    logging_config = {
        "level": logging.INFO,
        "format": LOG_FORMAT,
        "handlers": [],
    }
    if args.logfile:
        logging_config["handlers"].append(logging.FileHandler(args.logfile))
    else:
        logging_config["handlers"].append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(**logging_config)

    # Set up certificate generation
    if args.keep_certs:
        CERT_DIR = os.getcwd()
    else:
        CERT_DIR = tempfile.mkdtemp()

        def cleanup():
            logger.info("Removing temporary certificate directory")
            shutil.rmtree(CERT_DIR, ignore_errors=False)

        atexit.register(cleanup)
    logger.info("Certificate directory: %s", CERT_DIR)
    cert_path, key_path = read_or_create_cert()

    # Start and configure server
    server = MyHTTPServer(("127.0.0.1", args.port), ProxyHandler)
    server.delay = max(0, args.delay)

    # Enable interception if any response-related args are provided
    if any(x is not None for x in [args.return_code, args.return_data]) or args.return_header:
        server.intercept_mode = True
        server.return_code = args.return_code or 200
        server.return_data = args.return_data or ""

        # Parse headers
        server.return_headers = []
        if args.return_header:
            for header in args.return_header:
                try:
                    name, value = header.split(":", 1)
                    server.return_headers.append((name.strip(), value.strip()))
                except ValueError:
                    logger.error("Invalid header format: %s", header)
                    return 1
    server_thread = Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.info("Proxy server started on port %d", args.port)

    # Proxy configuration
    env = os.environ.copy()
    proxy_host = "http://localhost:%d" % args.port
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
