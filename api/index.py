from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import socket
import ssl

def get_audit_results(domain):
    # 1. DNS Verification Step (Check if domain is real)
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return {
            "score": 0,
            "vulnerabilities": [{
                "name": "Domain Inactive or Invalid",
                "description": "This domain could not be resolved. It is either unregistered, typoed, or not pointing to a live nameserver."
            }]
        }

    # Initialize baseline metrics
    score = 100
    vulnerabilities = []
    
    # 2. SSL/TLS Handshake Check (Port 443)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Handshake succeeded
                pass
    except Exception:
        score -= 50
        vulnerabilities.append({
            "name": "SSL Missing",
            "description": "The site does not support secure HTTPS connections on port 443."
        })

    # 3. HTTP to HTTPS Redirect Check (Port 80)
    try:
        with socket.create_connection((domain, 80), timeout=4) as sock:
            # Send a raw HTTP HEAD request to check for redirection headers
            request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for standard redirection status codes
            if "HTTP/1.1 30" not in response and "Location:" not in response:
                score -= 30
                vulnerabilities.append({
                    "name": "No HTTPS Redirect",
                    "description": "Traffic targeting unencrypted HTTP is not automatically forced over to HTTPS."
                })
    except Exception:
        # If port 80 fails to connect entirely while 443 works, we don't penalize harshly
        pass

    # Ensure score doesn't drop below 0
    final_score = max(0, score)

    return {
        "score": final_score,
        "vulnerabilities": vulnerabilities
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_components = parse_qs(parsed_path.query)
        domain = query_components.get('domain', [None])[0]

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        if not domain:
            self.wfile.write(json.dumps({"error": "No domain provided"}).encode())
            return

        # Clean domain string if passed with protocol by mistake
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0].strip()

        result = get_audit_results(domain)
        self.wfile.write(json.dumps(result).encode())
