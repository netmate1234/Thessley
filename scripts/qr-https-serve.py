#!/usr/bin/env python3
"""Serve the QR directory over HTTPS on 127.0.0.1 only.

    QR_DIR=/tmp/opencode/qr-site QR_PORT=8443 scripts/qr-https-serve.py

Creates a short-lived self-signed certificate for 127.0.0.1 on first run. It is
deliberately bound to loopback: approval links must never be exposed on the LAN
or a public site.
"""
import http.server
import os
import ssl
import subprocess
import sys

DIR = os.environ.get("QR_DIR", "/tmp/opencode/qr-site")
PORT = int(os.environ.get("QR_PORT", "8443"))
CERT = os.path.join(DIR, "cert.pem")
KEY = os.path.join(DIR, "key.pem")

os.makedirs(DIR, exist_ok=True)

if not (os.path.exists(CERT) and os.path.exists(KEY)):
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "7",
            "-nodes", "-keyout", KEY, "-out", CERT,
            "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

os.chdir(DIR)
server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
server.socket = ctx.wrap_socket(server.socket, server_side=True)

print(f"serving {DIR} on https://127.0.0.1:{PORT}", file=sys.stderr)
server.serve_forever()
