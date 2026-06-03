from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import requests

# Using a Session is more efficient for multiple requests
session = requests.Session()
session.max_redirects = 3 # Prevent redirect loops from hanging the audit

def get_audit_results(domain):
    # Clean the domain input just in case
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    url = f"https://{domain}"
    
    score = 100
    vulnerabilities = []
    headers = {}
    
    custom_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml"
    }

    try:
        # Tightened timeout to 5 seconds for the initial handshake
        response = session.get(url, timeout=5, verify=True, allow_redirects=True, headers=custom_headers)
        headers = {k.lower(): v for k, v in response.headers.items()}
    
    except requests.exceptions.SSLError:
        score -= 47
        vulnerabilities.append({
            "name": "SSL Issues Detected",
            "description": "Encryption is broken or missing. User data could be at risk."
        })
        # If SSL fails, try one quick non-verify grab
        try:
            low_sec_res = session.get(url, timeout=3, verify=False, allow_redirects=True, headers=custom_headers)
            headers = {k.lower(): v for k, v in low_sec_res.headers.items()}
        except:
            headers = {}

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return {"score": 0, "vulnerabilities": [{"name": "Unreachable", "description": "The website took too long to respond or the domain doesn't exist."}]}
    except Exception as e:
        return {"score": 0, "vulnerabilities": [{"name": "Scan Error", "description": "Could not complete the audit."}]}

    # --- Header Analysis ---
    if not headers:
        return {"score": 0, "vulnerabilities": [{"name": "No Data", "description": "Could not retrieve security headers."}]}

    # 1. Clickjacking
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        score -= 17 
        vulnerabilities.append({"name": "Missing Clickjacking Shield", "description": "Site is vulnerable to being embedded in malicious frames."})

    # 2. HSTS
    if "strict-transport-security" not in headers:
        score -= 12
        vulnerabilities.append({"name": "HSTS Not Active", "description": "Browser is not forced to use HTTPS for all requests."})

    # 3. Sniffing
    if "x-content-type-options" not in headers:
        score -= 12
        vulnerabilities.append({"name": "Missing Sniffing Protection", "description": "Prevents the browser from interpreting files as a different MIME type."})

    return {
        "score": max(0, score),
        "vulnerabilities": vulnerabilities
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        domain = params.get("domain", [None])[0]

        if not domain:
            self.send_response(400)
            self.end_headers()
            return

        result = get_audit_results(domain)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())
