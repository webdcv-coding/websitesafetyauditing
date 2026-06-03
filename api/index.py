from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import requests

def get_audit_results(domain):
    url = f"https://{domain}"
    score = 100
    vulnerabilities = []
    headers = {}
    
    custom_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }

    try:
        # Check the site with redirects followed
        response = requests.get(url, timeout=10, verify=True, allow_redirects=True, headers=custom_headers)
        headers = {k.lower(): v for k, v in response.headers.items()}
    
    except requests.exceptions.SSLError:
        score -= 47 # Softened deduction
        vulnerabilities.append({
            "name": "SSL Issues Detected",
            "description": "Encryption is broken or missing. User data could be at risk."
        })
        try:
            low_sec_res = requests.get(url, timeout=5, verify=False, allow_redirects=True, headers=custom_headers)
            headers = {k.lower(): v for k, v in low_sec_res.headers.items()}
        except:
            pass
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return {"score": 0, "vulnerabilities": [{"name": "Unreachable", "description": "Check the domain spelling."}]}
    except Exception:
        return {"score": 0, "vulnerabilities": [{"name": "Error", "description": "Audit failed to initialize."}]}

    # Security Header Checks (-3 from original suggestions)
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        score -= 17 
        vulnerabilities.append({
            "name": "Missing Clickjacking Shield",
            "description": "Your site could be loaded in a malicious iframe."
        })

    if "strict-transport-security" not in headers:
        score -= 12
        vulnerabilities.append({
            "name": "HSTS Not Active",
            "description": "Browser is not forced to use HTTPS for all requests."
        })

    if "x-content-type-options" not in headers:
        score -= 12
        vulnerabilities.append({
            "name": "Missing Sniffing Protection",
            "description": "The browser might try to guess the file type, enabling injection."
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
            self.end_headers()
            return

        result = get_audit_results(domain)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())
