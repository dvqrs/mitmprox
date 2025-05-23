#!/usr/bin/env python3
"""
Simple CA-giver:

Serves ~/.mitmproxy/mitmproxy-ca-cert.pem over HTTP port 8080.
"""

import os
import http.server
import socketserver
import sys

# ────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────
CA_PATH   = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
HTTP_PORT = 8080

# ────────────────────────────────────────────────────
# HTTP handler for CA download
# ────────────────────────────────────────────────────
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

# ────────────────────────────────────────────────────
# Entrypoint
# ────────────────────────────────────────────────────
def main():
    httpd = socketserver.TCPServer(("", HTTP_PORT), CARequestHandler)
    print(f"[*] Serving CA on http://0.0.0.0:{HTTP_PORT}/mitmproxy-ca-cert.pem")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down CA server...")
        httpd.server_close()
        sys.exit(0)

if __name__ == "__main__":
    main()
