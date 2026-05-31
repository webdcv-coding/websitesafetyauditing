from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import urllib.error
import json
import socket
import ssl

def get_audit_results(domain):
    # 1. DNS Verification
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return {
            "score": 0,
            "vulnerabilities": [{
                "name": "Domain Inactive",
                "description": "This domain could not be resolved. Verify the spelling."
            }]
        }

    score = 100
    vulnerabilities = []
    
    # 2. SSL/TLS & Header-based Checks
    ctx = ssl.create_default_context()
    
    # Standard User-Agent to ensure compatibility with most servers
    req = urllib.request.Request(
        f"https://{domain}/",
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )

    try:
        # urlopen automatically follows redirects
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            headers = {k.lower(): v for k, v in response.getheaders()}
    except urllib.error.HTTPError as e:
        # Capture headers even if the page returns a 403/404 error
        headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception:
        score -= 40
        vulnerabilities.append({
            "name": "SSL Missing or Broken",
            "description": "Failed to establish a secure, validated HTTPS handshake."
        })
        return {"score": max(0, score), "vulnerabilities": vulnerabilities}

    # HSTS Check
    if 'strict-transport-security' not in headers:
        score -= 30
        vulnerabilities.append({
            "name": "HSTS Missing",
            "description": "The site does not use HSTS to force secure connections."
        })
        
    # Clickjacking Check
    has_clickjack = 'x-frame-options' in headers or 'content-security-policy' in headers
    if not has_clickjack:
        score -= 30
        vulnerabilities.append({
            "name": "Clickjacking Vulnerability",
            "description": "Missing X-Frame-Options or CSP headers."
        })

    return {"score": max(0, score), "vulnerabilities": vulnerabilities}

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        domain = query_components.get('domain', [None])[0]

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        if domain:
            clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0].strip()
            result = get_audit_results(clean_domain)
            self.wfile.write(json.dumps(result).encode())
