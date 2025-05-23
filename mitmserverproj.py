#!/usr/bin/env python3
"""
MITM Firewall Proxy Script.

- When run directly: spawns mitmproxy itself on port 8443 with this file as the addon.
- When loaded by mitmproxy: registers the firewall addon to inspect and block traffic.
"""
import sys
import subprocess
import signal
import os

# --- Addon Code ---
import base64
import requests
from mitmproxy import http, ctx

VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VT_API_KEY")
BLOCK_MALICIOUS = True            # Whether to block malicious URLs

class MitmFirewall:
    def __init__(self):
        ctx.log.info("MITM Firewall addon initialized.")

    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        ctx.log.info(f"[REQUEST] {url}")
        if BLOCK_MALICIOUS and self.is_malicious(url):
            ctx.log.warn(f"Blocking malicious URL: {url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<html><body><h1>403 Forbidden</h1><p>Blocked by MITM firewall proxy.</p></body></html>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        body = flow.response.get_text()
        if "malware-signature" in body.lower():
            ctx.log.warn(f"Blocking malicious content at: {flow.request.pretty_url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<html><body><h1>403 Forbidden</h1><p>Blocked malicious content.</p></body></html>",
                {"Content-Type": "text/html"}
            )

    def is_malicious(self, url: str) -> bool:
        # URL-safe Base64 without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        try:
            resp = requests.get(vt_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return stats.get("malicious", 0) > 0
            ctx.log.warn(f"VT lookup HTTP {resp.status_code} for {url}")
        except Exception as e:
            ctx.log.error(f"Error querying VT for {url}: {e}")
        return False

addons = [MitmFirewall()]

# --- Entrypoint for direct execution ---
if __name__ == "__main__":
    # Spawn mitmproxy process with this script as addon
    cmd = [
        "mitmproxy",
        "-p", "8443",
        "--ssl-insecure",
        "-s", sys.argv[0]
    ]
    print(f"[*] Launching mitmproxy: {' '.join(cmd)}")
    p = subprocess.Popen(cmd)

    def shutdown(signum, frame):
        print("[*] Shutting down mitmproxy...")
        p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    p.wait()
