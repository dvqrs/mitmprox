"""
Runs mitmdump on port 8443, serving its built-in CA and your firewall logic.
"""

import os, sys, signal, subprocess
from mitmproxy import http

VT_API_KEY = os.getenv("VT_API_KEY", "<your-vt-api-key>")
BLOCK_MALICIOUS = True

def is_malicious(url: str) -> bool:
    import base64, requests
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": VT_API_KEY}, timeout=10
    )
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) > 0
    return False

class MitmFirewall:
    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        print(f"[REQUEST] {url}")
        # Serve CA from mitmproxy storage
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            ca = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
            data = open(ca, "rb").read()
            flow.response = http.HTTPResponse.make(200, data,
                                                   {"Content-Type": "application/x-pem-file"})
            return
        # Block via VT
        if BLOCK_MALICIOUS and is_malicious(url):
            flow.response = http.HTTPResponse.make(
                403,
                b"<h1>Blocked by MITM firewall</h1>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        # optionally inspect response bodies here…

        pass

addons = [MitmFirewall()]

if __name__ == "__main__":
    cmd = [
        "mitmdump",
        "-p", "8443",
        "--ssl-insecure",
        "-s", sys.argv[0],
        "--set", "client_http2=true",
        "--set", "server_http2=true",
    ]
    print(f"[*] Starting mitmdump: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd)
    def shutdown(sig, frame):
        print("[*] Shutting down…")
        proc.terminate()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    proc.wait()
