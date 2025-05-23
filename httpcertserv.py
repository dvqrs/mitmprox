#!/usr/bin/env python3
"""
Combined MITM firewall + CA‐distribution.

1) Serves the CA file over plain HTTP port 8080 so clients can fetch it without TLS.
2) Runs mitmdump on port 8443 with your existing addon logic.
"""

import os
import sys
import threading
import http.server
import socketserver
import signal
import subprocess

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
CA_PATH      = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
HTTP_PORT    = 8080
MITM_PORT    = 8443

# ──────────────────────────────────────────────────────────────────────────────
# 1) Simple HTTP server to serve the CA file
# ──────────────────────────────────────────────────────────────────────────────
class CARequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/mitmproxy-ca-cert.pem", "/"):
            if not os.path.isfile(CA_PATH):
                self.send_error(404, "CA not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", os.path.getsize(CA_PATH))
            self.end_headers()
            with open(CA_PATH, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404)

def start_ca_server():
    handler = CARequestHandler
    # Serve only CA_PATH, no directory listing
    httpd = socketserver.TCPServer(("", HTTP_PORT), handler)
    print(f"[*] Serving CA bundle on http://0.0.0.0:{HTTP_PORT}/mitmproxy-ca-cert.pem")
    httpd.serve_forever()

# ──────────────────────────────────────────────────────────────────────────────
# 2) Spawn mitmdump with your addon (this file itself)
# ──────────────────────────────────────────────────────────────────────────────
def start_mitmdump():
    cmd = [
        "mitmdump",
        "-p", str(MITM_PORT),
        "--ssl-insecure",
        "-s", sys.argv[0],
        "--set", "client_http2=true",
        "--set", "server_http2=true",
    ]
    print(f"[*] Starting mitmdump: {' '.join(cmd)}")
    return subprocess.Popen(cmd)

# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 1) Launch CA‐server in background
    ca_thread = threading.Thread(target=start_ca_server, daemon=True)
    ca_thread.start()

    # 2) Launch mitmdump
    mitm_proc = start_mitmdump()

    # 3) Graceful shutdown
    def shutdown(signum, frame):
        print("[*] Shutting down mitmdump and CA server...")
        mitm_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    mitm_proc.wait()
