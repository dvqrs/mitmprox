#!/usr/bin/env python3
"""
Standalone MITM Firewall Proxy using mitmproxy's programmatic API.
Run directly with `python mitm_firewall_proxy.py` and it will start listening on port 8443.
"""
import base64
import requests
import signal
import sys
import asyncio

from mitmproxy import http, ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

# --- Configuration ---
VT_API_KEY = "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416"  # Replace with your VirusTotal API key
BLOCK_MALICIOUS = True            # Whether to block malicious URLs
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8443
SSL_INSECURE = True               # Allow intercepting HTTPS without CA errors

# --- Helper Functions ---
def encode_url(url: str) -> str:
    """URL-safe Base64 encode (no padding) for VirusTotal URL ID."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def is_url_malicious(url: str) -> bool:
    """Query VirusTotal API; return True if malicious count > 0."""
    url_id = encode_url(url)
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        resp = requests.get(vt_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats.get("malicious", 0) > 0
        ctx.log.warn(f"VirusTotal HTTP {resp.status_code} for {url}")
    except Exception as e:
        ctx.log.error(f"Error contacting VirusTotal for {url}: {e}")
    return False

# --- MITM Addon Class ---
class MitmFirewall:
    def __init__(self):
        ctx.log.info("Initializing MITM Firewall addon...")

    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        ctx.log.info(f"[REQUEST] {url}")
        if BLOCK_MALICIOUS and is_url_malicious(url):
            ctx.log.warn(f"Blocking malicious URL: {url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<html><body><h1>403 Forbidden</h1><p>Blocked by MITM firewall proxy.</p></body></html>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        content = flow.response.get_text()
        if "malware-signature" in content.lower():
            ctx.log.warn(f"Blocking response content for URL: {flow.request.pretty_url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<html><body><h1>403 Forbidden</h1><p>Blocked content detected.</p></body></html>",
                {"Content-Type": "text/html"}
            )

# --- Main Entrypoint ---
def start_proxy():
    # Ensure there's an asyncio event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    opts = Options(
        listen_host=LISTEN_HOST,
        listen_port=LISTEN_PORT,
        ssl_insecure=SSL_INSECURE
    )
    master = DumpMaster(opts, event_loop=loop, with_termlog=False, with_dumper=False)
    master.addons.add(MitmFirewall())

    # Handle clean shutdown
    def shutdown(signal_num, frame):
        ctx.log.info("Shutting down proxy...")
        master.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    ctx.log.info(f"Starting MITM firewall proxy on {LISTEN_HOST}:{LISTEN_PORT}")
    try:
        master.run()
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == "__main__":
    start_proxy()
