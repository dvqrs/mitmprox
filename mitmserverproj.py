from mitmproxy import http, ctx
import base64
import requests

# --- Configuration ---
VT_API_KEY = "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416"  # Replace with your VirusTotal API key
BLOCK_MALICIOUS = True            # Whether to block malicious URLs

# --- Helper Functions ---
def encode_url(url: str) -> str:
    """
    Encode the URL using URL-safe Base64 encoding without padding.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def is_url_malicious(url: str) -> bool:
    """
    Query VirusTotal API for the given URL. Return True if any engine reports malicious.
    """
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

# --- mitmproxy hooks ---
def request(flow: http.HTTPFlow) -> None:
    """
    Called when a client request is received. We inspect and decide to block or allow.
    """
    url = flow.request.pretty_url
    ctx.log.info(f"Request URL: {url}")
    if BLOCK_MALICIOUS and is_url_malicious(url):
        ctx.log.warn(f"Blocking malicious URL: {url}")
        flow.response = http.HTTPResponse.make(
            403,  # HTTP status code
            b"<html><body><h1>403 Forbidden</h1><p>Blocked by MITM firewall proxy.</p></body></html>",
            {"Content-Type": "text/html"}
        )


def response(flow: http.HTTPFlow) -> None:
    """
    Called when server response is available. You can inspect content here.
    e.g., block known malicious payloads in response body (optional).
    """
    # Example: block if response contains "malware-signature"
    content = flow.response.get_text()
    if "malware-signature" in content.lower():
        ctx.log.warn(f"Blocking response content for URL: {flow.request.pretty_url}")
        flow.response = http.HTTPResponse.make(
            403,
            b"<html><body><h1>403 Forbidden</h1><p>Blocked content detected.</p></body></html>",
            {"Content-Type": "text/html"}
        )


def start():
    """
    Called once when mitmproxy starts.
    """
    ctx.log.info("MITM firewall proxy addon loaded.")
    ctx.log.info("Ensure clients trust this proxy's CA certificate.")
    ctx.log.info("Run mitmproxy with: mitmproxy -p 8443 --ssl-insecure -s mitm_firewall_proxy.py")
