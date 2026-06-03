from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import requests # Using requests as defined in your requirements.txt

def get_audit_results(domain):
    # Ensure the domain has a scheme for the requests library
    url = f"https://{domain}"
    
    score = 100
    vulnerabilities = []
    
    try:
        # 1. Check for SSL and Connection
        # timeout=10 prevents the function from hanging
        response = requests.get(url, timeout=10, verify=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
    except requests.exceptions.SSLError:
        return {
            "score": 0,
            "vulnerabilities": [{
                "name": "SSL Broken or Invalid",
                "description": "The site has an invalid or expired SSL certificate."
            }]
        }
    except Exception as e:
        return {
            "score": 0,
            "vulnerabilities": [{
                "name": "Connection Failed",
                "description": f"Could not connect to {domain}. Verify the URL."
            }]
        }

    # 2. Check X-Frame-Options (Clickjacking)
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        score -= 40
        vulnerabilities.append({
            "name": "Missing Clickjacking Protection",
            "description": "Missing X-Frame-Options or CSP 'frame-ancestors' header."
        })
    elif "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
         # Double check CSP if X-Frame is missing
         score -= 40
         vulnerabilities.append({
            "name": "Weak Clickjacking Protection",
            "description": "No explicit X-Frame-Options found."
        })

    # 3. Check HSTS (Strict-Transport-Security)
    if "strict-transport-security" not in headers:
        score -= 30
        vulnerabilities.append({
            "name": "Missing HSTS",
            "description": "Strict-Transport-Security header not found. Site is vulnerable to SSL stripping."
        })

    # 4. Check X-Content-Type-Options
    if "x-content-type-options" not in headers:
        score -= 30
        vulnerabilities.append({
            "name": "Missing X-Content-Type-Options",
            "description": "The browser may perform MIME-type sniffing."
        })

    return {
        "score": max(0, score),
        "vulnerabilities": vulnerabilities
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse query parameters
        parsed_path = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_path.query)
        domain = params.get("domain", [None])[0]

        if not domain:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "No domain provided"}).encode())
            return

        # Perform Audit
        result = get_audit_results(domain)

        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        # Crucial for local testing or cross-origin setups
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.end_headers()
        
        self.wfile.write(json.dumps(result).encode())
        return
