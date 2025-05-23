#!/usr/bin/env python3
"""
mitmproxy firewall only (no built-in CA server).

This listens on port 8443 as an HTTP proxy (CONNECT).  CA distribution is handled by a separate service.
"""

import os
import sys
import signal
import subprocess
import base64
import requests

from mitmproxy import http

# ────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────
MITM_PORT    = 8443
VT_API_KEY   = os.getenv("VT_API_KEY", "<your-virustotal-api-key>")
BLOCK_MALICIOUS = True

# ────────────────────────────────────────────────────
# VirusTotal URL reputation check
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

# ────────────────────────────────────────────────────
# mitmproxy addon for VT-based blocking
# ────────────────────────────────────────────────────
class MitmFirewall:
    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        print(f"[REQUEST] {url}")

        # Block if flagged malicious
        if BLOCK_MALICIOUS and is_malicious(url):
            print(f"[BLOCK] {url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        # (Optionally inspect response bodies here)
        pass

addons = [MitmFirewall()]

# ────────────────────────────────────────────────────
# Entrypoint: just mitmdump on 8443
# ────────────────────────────────────────────────────
if __name__ == "__main__":
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
        print("[*] Shutting down mitmproxy…")
        proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    proc.wait()
