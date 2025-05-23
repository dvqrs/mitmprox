#!/usr/bin/env python3
"""
Simple CA-giver:

Serves the mitmproxy CA file over HTTP on the port Railway assigns.

Set MITMPROXY_CA_PATH to override the default path.
"""

import os
import sys
import http.server
import socketserver

# ────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────
# Allow overriding CA location via environment
CA_PATH   = os.environ.get("MITMPROXY_CA_PATH",
            os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"))
# Railway sets PORT for incoming HTTP
HTTP_PORT = int(os.environ.get("PORT", "8080"))

class CARequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"[*] CA-giver: GET {self.path} from {self.client_address}")
        if self.path in ("/mitmproxy-ca-cert.pem", "/"):
            if not os.path.isfile(CA_PATH):
                print(f"[!] CA file not found at {CA_PATH}")
                return self.send_error(404, "CA not found")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", os.path.getsize(CA_PATH))
            self.end_headers()
            with open(CA_PATH, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404)


def main():
    addr = ("", HTTP_PORT)
    httpd = socketserver.TCPServer(addr, CARequestHandler)
    print(f"[*] Serving CA on http://0.0.0.0:{HTTP_PORT}/mitmproxy-ca-cert.pem")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down CA server…")
        httpd.server_close()
        sys.exit(0)

if __name__ == "__main__":
    main()
