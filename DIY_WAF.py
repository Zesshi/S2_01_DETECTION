import sys
import json
import requests
import argparse
import urllib.parse  # <-- Needed to decode URL-encoded attacks
from http.server import BaseHTTPRequestHandler, HTTPServer

class WafHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server, p_host=None, p_port=None, u_host=None, u_port=None, payloads=None):
        self.p_host = p_host
        self.p_port = p_port
        self.u_host = u_host
        self.u_port = u_port
        self.payloads = [payload.strip().lower() for payload in payloads if payload.strip()] if payloads else []
        self.hop_by_hop_headers = [
            "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "trailer",
            "proxy-authorization", "proxy-authenticate", "upgrade"
        ]
        super().__init__(request, client_address, server)

    def clean_headers(self, headers):
        """ Remove hop-by-hop headers but keep necessary ones """
        return {key: value for key, value in headers.items() if key.lower() not in self.hop_by_hop_headers}

    def detect_attack(self, input_data):
        """ Check if any attack payload from payloads.txt appears in the input """
        decoded_input = urllib.parse.unquote(input_data.lower())  # Decode URL encoding
        for payload in self.payloads:
            if payload in decoded_input:
                print("\n" + "=" * 60)
                print(f"[!] BLOCKED ATTACK DETECTED")
                print(f"[!] Matched Payload: {payload}")
                print("=" * 60 + "\n")
                return True
        return False

    def do_GET(self):
        """ Handle GET requests by forwarding them to the upstream server """
        print(f"[i] GET request received: {self.path}")

        if self.detect_attack(self.path):  # Check if URL parameters contain malicious content
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Blocked: Malicious content detected"}')
            return

        clean_header = self.clean_headers(self.headers)
        upstream_url = f"http://{self.u_host}:{self.u_port}{self.path}"

        upstream_response = requests.get(upstream_url, headers=clean_header, allow_redirects=False)

        self.send_response(upstream_response.status_code)
        for key, value in upstream_response.headers.items():
            if key.lower() not in self.hop_by_hop_headers:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(upstream_response.content)

    def do_POST(self):
        """ Handle POST requests by forwarding them to the upstream server """
        print(f"[i] POST request received: {self.path}")
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")  # Ensure post_data is a string

        if self.detect_attack(post_data):
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Blocked: Malicious content detected"}')
            return  # Stop further processing

        clean_header = self.clean_headers(self.headers)
        upstream_url = f"http://{self.u_host}:{self.u_port}{self.path}"

        upstream_response = requests.post(upstream_url, headers=clean_header, data=post_data, allow_redirects=False)

        self.send_response(upstream_response.status_code)
        for key, value in upstream_response.headers.items():
            if key.lower() not in self.hop_by_hop_headers:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(upstream_response.content)

def load_payloads(file_path):
    """ Load known attack payloads from a file """
    with open(file_path, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]  # Remove empty lines

def start_waf(p_host, p_port, u_host, u_port, payloads):
    print("\n" + "=" * 60)
    print(f"[i] Starting WAF...")
    print(f"[i] Proxy Server is listening on: {p_host}:{p_port}")
    print(f"[i] Upstream webserver: {u_host}:{u_port}")
    print("=" * 60 + "\n")

    handler = lambda request, client_address, server: WafHTTPRequestHandler(
        request, client_address, server, p_host, p_port, u_host, u_port, payloads)
    server = HTTPServer((p_host, p_port), handler)
    server.serve_forever()

def main():
    parser = argparse.ArgumentParser(
        prog='DIY WAF',
        description='Simple Web Proxy that detects attacks from a provided payload list.')
    parser.add_argument('payload_path', help="Path to the file with the attack payloads.")
    parser.add_argument('p_host', help="Proxy host.")
    parser.add_argument('p_port', help="Proxy port.", type=int)
    parser.add_argument('u_host', help="Upstream host.")
    parser.add_argument('u_port', help="Upstream port.", type=int)
    args = parser.parse_args()

    payloads = load_payloads(args.payload_path)
    start_waf(args.p_host, args.p_port, args.u_host, args.u_port, payloads)

if __name__ == "__main__":
    main()
 
