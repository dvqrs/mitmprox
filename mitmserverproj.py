#!/usr/bin/env python3
"""
Combined MITM CA‐distribution + firewall.

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
import base64
import requests

from mitmproxy import http

# ────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────
CA_PATH   = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
HTTP_PORT = 8080
MITM_PORT = 8443
VT_API_KEY = os.getenv("VT_API_KEY", "<your-virustotal-api-key>")
BLOCK_MALICIOUS = True

# ────────────────────────────────────────────────────
# 1) Simple HTTP server to serve the CA file
# ────────────────────────────────────────────────────
class CARequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/mitmproxy-ca-cert.pem", "/"):
            if not os.path.isfile(CA_PATH):
                return self.send_error(404, "CA not found")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", os.path.getsize(CA_PATH))
            self.end_headers()
            with open(CA_PATH, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404)

def start_ca_server():
    httpd = socketserver.TCPServer(("", HTTP_PORT), CARequestHandler)
    print(f"[*] Serving CA on http://0.0.0.0:{HTTP_PORT}/mitmproxy-ca-cert.pem")
    httpd.serve_forever()

# ────────────────────────────────────────────────────
# 2) mitmproxy addon for VT-based blocking
# ────────────────────────────────────────────────────
def is_malicious(url: str) -> bool:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": VT_API_KEY},
        timeout=10
    )
    if resp.status_code == 200:
        stats = resp.json().get("data", {})\
                       .get("attributes", {})\
                       .get("last_analysis_stats", {})
        return stats.get("malicious", 0) > 0
    return False

class MitmFirewall:
    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        print(f"[REQUEST] {url}")

        # serve CA directly if fetched via CONNECT-then-GET
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            data = open(CA_PATH, "rb").read()
            flow.response = http.HTTPResponse.make(
                200, data, {"Content-Type": "application/x-pem-file"}
            )
            return

        # block malicious
        if BLOCK_MALICIOUS and is_malicious(url):
            print(f"[BLOCK] {url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        # optionally inspect response bodies here…
        pass

# ────────────────────────────────────────────────────
# Entrypoint
# ────────────────────────────────────────────────────
if __name__ == "__main__":
    # 1) Launch CA server thread
    threading.Thread(target=start_ca_server, daemon=True).start()

    # 2) Launch mitmdump
    cmd = [
        "mitmdump",
        "-p", str(MITM_PORT),
        "--ssl-insecure",
        "-s", sys.argv[0],
        "--set", "client_http2=true",
        "--set", "server_http2=true",
    ]
    print(f"[*] Starting mitmdump: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd)

    def shutdown(signum, frame):
        print("[*] Shutting down…")
        proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    proc.wait()
