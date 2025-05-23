import os
import http.server
import socketserver

# Use env or fallback to ~/.mitmproxy path
CA_PATH = os.environ.get("MITMPROXY_CA_PATH", os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"))
PORT = int(os.environ.get("PORT", 8080))

class CARequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"[*] CA-giver: GET {self.path} from {self.client_address}")
        if self.path in ("/", "/favicon.ico"):
            if not os.path.isfile(CA_PATH):
                print(f"[!] CA file not found at {CA_PATH}")
                self.send_error(404, "CA not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", os.path.getsize(CA_PATH))
            self.end_headers()
            with open(CA_PATH, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Not Found")

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), CARequestHandler) as httpd:
        print(f"[*] Serving CA on http://0.0.0.0:{PORT}/")
        httpd.serve_forever()
