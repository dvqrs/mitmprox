#!/usr/bin/env python3
"""
MITM Firewall Proxy Script using mitmdump.

Run with:
```bash
python mitm_firewall_proxy.py
```
It will spawn `mitmdump` on port 8443 (no console UI) and use this file as the addon.
"""
import sys
import subprocess
import signal
import os
import base64
import requests
from mitmproxy import http

# Configuration
VT_API_KEY = os.getenv("0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416", "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416")
BLOCK_MALICIOUS = True  # Toggle URL blocking

# Helper: VT lookup
def is_malicious(url: str) -> bool:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        resp = requests.get(vt_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats.get("malicious", 0) > 0
        print(f"[WARN] VT HTTP {resp.status_code} for {url}")
    except Exception as e:
        print(f"[ERROR] VT query failed for {url}: {e}")
    return False

class MitmFirewall:
    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        print(f"[REQUEST] {url}")
        if BLOCK_MALICIOUS and is_malicious(url):
            print(f"[BLOCK] Malicious URL: {url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<html><body><h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p></body></html>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            body = flow.response.get_text()
            if "malware-signature" in body.lower():
                print(f"[BLOCK] Malicious content at: {flow.request.pretty_url}")
                flow.response = http.HTTPResponse.make(
                    403,
                    b"<html><body><h1>403 Forbidden</h1><p>Blocked malicious content.</p></body></html>",
                    {"Content-Type": "text/html"}
                )
        except Exception:
            pass

addons = [MitmFirewall()]

# Entrypoint: spawn mitmdump
if __name__ == "__main__":
    cmd = [
        "mitmdump",
        "-p", "8443",
        "--ssl-insecure",
        "-s", sys.argv[0]
    ]
    print(f"[*] Starting mitmdump: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd)

    def shutdown(signum, frame):
        print("[*] Shutting down mitmdump...")
        proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    proc.wait()
