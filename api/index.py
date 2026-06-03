from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import requests

def get_audit_results(domain):
    url = f"https://{domain}"
    score = 100
    vulnerabilities = []
    headers = {}

    # 1. Primary Connection & SSL Check
    try:
        # We use a session to better manage the connection
        response = requests.get(url, timeout=10, verify=True, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
    
    except requests.exceptions.SSLError:
        # Site exists but SSL is broken/missing
        score -= 50 
        vulnerabilities.append({
            "name": "Invalid or Missing SSL",
            "description": "The site is reachable but does not provide a valid SSL certificate. Traffic is not secure."
        })
        # Try to get headers anyway without SSL verification to see if the site is up
        try:
            low_sec_res = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            headers = {k.lower(): v for k, v in low_sec_res.headers.items()}
        except:
            pass

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return {
            "score": 0,
            "vulnerabilities": [{
                "name": "Domain Unreachable",
                "description": "Could not connect to the domain. Please check the spelling or your internet connection."
            }]
        }
    except Exception as e:
        return {
            "score": 0,
            "vulnerabilities": [{
                "name": "Audit Error",
                "description": "An unexpected error occurred during the scan."
            }]
        }

    # 2. Check X-Frame-Options (Clickjacking)
    # Checking both X-Frame and CSP for ancestors
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        score -= 20
        vulnerabilities.append({
            "name": "Missing Clickjacking Protection",
            "description": "The site is missing X-Frame-Options or a CSP frame-ancestors directive."
        })

    # 3. Check HSTS (Strict-Transport-Security)
    if "strict-transport-security" not in headers:
        score -= 15
        vulnerabilities.append({
            "name": "Missing HSTS",
            "description": "HSTS is not enabled. Browsers aren't forced to use secure connections."
        })

    # 4. Check X-Content-Type-Options
    if "x-content-type-options" not in headers:
        score -= 15
        vulnerabilities.append({
            "name": "Missing X-Content-Type-Options",
            "description": "The browser is allowed to 'sniff' the content type, which can lead to script injection."
        })

    return {
        "score": max(0, score),
        "vulnerabilities": vulnerabilities
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_path.query)
        domain = params.get("domain", [None])[0]

        if not domain:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "No domain provided"}).encode())
            return

        result = get_audit_results(domain)

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.end_headers()
        
        self.wfile.write(json.dumps(result).encode())
