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
                "description": "This domain could not be resolved. Verify the spelling or domain registration status."
            }]
        }

    score = 100
    vulnerabilities = []
    
    # 2. SSL/TLS & Header-based Checks (Following Redirects)
    ctx = ssl.create_default_context()
    
    # Adding a standard User-Agent prevents firewalls from blocking the audit
    req = urllib.request.Request(
        f"https://{domain}/",
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )

    try:
        # urlopen automatically follows 301/302 redirects to find the final headers
        response = urllib.request.urlopen(req, context=ctx, timeout=5)
        headers = {k.lower(): v for k, v in response.getheaders()}
    except urllib.error.HTTPError as e:
        # If the site returns a 403 or 404 but still has SSL, grab the headers anyway
        headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception:
        score -= 40
        vulnerabilities.append({
            "name": "SSL Missing or Broken",
            "description": "Failed to establish a secure, validated HTTPS handshake with this server."
        })
        return {
            "score": max(0, score),
            "vulnerabilities": vulnerabilities
        }

    # Check: HSTS (Strict-Transport-Security)
    if 'strict-transport-security' not in headers:
        score -= 30
        vulnerabilities.append({
            "name": "HSTS Missing",
            "description": "The site does not use HTTP Strict Transport Security (HSTS). Browsers are not forced to maintain a secure connection."
        })
        
    # Check: Clickjacking Protection
    has_clickjack_protection = False
    if 'x-frame-options' in headers:
        has_clickjack_protection = True
    elif 'content-security-policy' in headers:
        csp = headers.get('content-security-policy', '')
        if 'frame-ancestors' in csp:
            has_clickjack_protection = True

    if not has_clickjack_protection:
        score -= 30
        vulnerabilities.append({
            "name": "Clickjacking Vulnerability",
            "description": "Missing X-Frame-Options or Content-Security-Policy (frame-ancestors) headers. The site can be embedded in malicious iframes."
        })

    return {
        "score": max(0, score),
        "vulnerabilities": vulnerabilities
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_components = parse_qs(parsed_path.query)
        domain_list = query_components.get('domain', [None])
        domain = domain_list[0]

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        if not domain:
            self.wfile.write(json.dumps({"error": "No domain provided"}).encode())
            return

        clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0].strip()
        result = get_audit_results(clean_domain)
        self.wfile.write(json.dumps(result).encode())
