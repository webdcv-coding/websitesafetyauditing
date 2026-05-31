from http.server import BaseHTTPRequestHandler
import json
import ssl
import socket
import requests
from urllib.parse import urlparse, parse_qs

# --- AUDIT LOGIC ---
def check_ssl(domain):
    try:
        # Simplistic SSL check: attempt a connection to port 443
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except:
        return False

def get_audit_results(domain):
    # Ensure domain is just the hostname
    domain = domain.replace("https://", "").replace("http://", "").split('/')[0]
    
    score = 100
    vulnerabilities = []

    # SSL Check
    if not check_ssl(domain):
        score -= 60
        vulnerabilities.append({"name": "SSL Missing", "description": "The site does not support secure HTTPS connections."})
    
    # Simple HTTP check
    try:
        r = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
        if r.status_code != 301 and r.status_code != 302:
            score -= 20
            vulnerabilities.append({"name": "No HTTPS Redirect", "description": "Traffic is not being redirected to HTTPS."})
    except:
        pass

    return {
        "score": max(0, score),
        "vulnerabilities": vulnerabilities
    }

# --- SERVER HANDLER ---
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse query params
        parsed_path = urlparse(self.path)
        query_components = parse_qs(parsed_path.query)
        domain = query_components.get('domain', [None])[0]

        # Allow CORS
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        if not domain:
            self.wfile.write(json.dumps({"error": "No domain"}).encode())
            return

        # Run Audit
        result = get_audit_results(domain)
        self.wfile.write(json.dumps(result).encode())
